from __future__ import annotations

import gzip
import io
from binascii import crc32
from typing import BinaryIO, Iterator, Optional, TextIO

from dissect.util import cpio
from dissect.util.stream import OverlayStream

from dissect.target.filesystem import Filesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target


class FortigatePlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)

        self._config = None
        if config_file := self._find_config_file():
            with config_file as fh:
                self._config = FortigateConfig.from_fh(fh)

    def _find_config_file(self) -> Optional[TextIO]:
        fh = None

        if (conf := self.target.fs.path("/data/system.conf")).exists():
            fh = conf.open("rt")
        elif (conf := self.target.fs.path("/data/config/sys_global.conf.gz")).exists():
            fh = gzip.open(conf.open("rb"), "rt")

        return fh

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            # Tested on FortiGate and FortiAnalyzer, other Fortinet devices look different
            if fs.exists("/rootfs.gz") and (fs.exists("/.fgtsum") or fs.exists("/.fmg_sign")):
                return fs

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> FortigatePlugin:
        rootfs = sysvol.path("/rootfs.gz")
        vfs = TarFilesystem(rootfs.open(), tarinfo=cpio.CpioInfo)

        target.fs.mount("/", vfs)
        target.fs.mount("/data", sysvol)

        # FortiGate
        if (datafs_tar := sysvol.path("datafs.tar.gz")).exists():
            target.fs.add_layer().mount("/data", TarFilesystem(datafs_tar.open("rb")))

        # Additional FortiGate tars with corrupt XZ streams
        for path in ("bin.tar.xz", "usr.tar.xz", "migadmin.tar.xz", "node-scripts.tar.xz"):
            if (tar := target.fs.path(path)).exists():
                fh = repair_lzma_stream(tar.open("rb"))
                target.fs.add_layer().mount("/", TarFilesystem(fh))

        # FortiAnalyzer
        if (rootfs_ext_tar := sysvol.path("rootfs-ext.tar.xz")).exists():
            target.fs.add_layer().mount("/", TarFilesystem(rootfs_ext_tar.open("rb")))

        for fs in target.filesystems:
            # TODO: Figure out the other partitions
            # TODO: How to determine /data2?
            if fs.__type__ == "ext" and fs.extfs.volume_name.startswith("LOGUSEDX"):
                target.fs.mount("/var/log", fs)

        return cls(target)

    @export(property=True)
    def hostname(self) -> str | None:
        try:
            return self.config["system"]["global"]["hostname"][0]
        except KeyError:
            return None

    @export(property=True)
    def ips(self) -> list[str]:
        result = []

        try:
            for conf in self.config.system.interface.values():
                if "ip" in conf:
                    result.append(conf.ip[0])
        except KeyError:
            pass

        return result

    @export(property=True)
    def version(self) -> str:
        if config_fh := self._find_config_file():
            with config_fh:
                return config_fh.readline().split("=")[1]

        return "FortiOS Unknown"

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.FORTIGATE.value

    @export(record=UnixUserRecord)
    def users(self) -> Iterator[UnixUserRecord]:
        # TODO: Add FortiOS specific users
        return super().users()


def repair_lzma_stream(fh: BinaryIO) -> BinaryIO:
    """Repair CRC32 checksums for all headers in an XZ stream.

    Fortinet XZ files have (on purpose) corrupt streams which they read using a modified ``xz`` binary.
    The only thing changed are the CRC32 checksums, so partially parse the XZ file and fix all of them.

    References:
        - https://tukaani.org/xz/xz-file-format-1.1.0.txt
        - https://github.com/Rogdham/python-xz

    Args:
        fh: A file-like object of an LZMA stream to repair.
    """
    size = fh.seek(0, io.SEEK_END)
    repaired = OverlayStream(fh, size)
    fh.seek(0)

    header = fh.read(12)
    # Check header magic
    if header[:6] != b"\xfd7zXZ\x00":
        raise ValueError("Not an XZ file")
    # Add correct header CRC32
    repaired.add(8, _crc32(header[6:8]))

    fh.seek(-12, io.SEEK_END)
    footer = fh.read(12)
    # Check footer magic
    if footer[10:12] != b"YZ":
        raise ValueError("Not an XZ file")
    # Add correct footer CRC32
    repaired.add(fh.tell() - 12, _crc32(footer[4:10]))

    backward_size = (int.from_bytes(footer[4:8], "little") + 1) * 4
    fh.seek(-12 - backward_size, io.SEEK_END)
    index = fh.read(backward_size)
    # Add correct index CRC32
    repaired.add(fh.tell() - 4, _crc32(index[:-4]))

    # Parse the index
    isize, nb_records = _mbi(index[1:])
    index = index[1 + isize : -4]
    records = []
    for _ in range(nb_records):
        if not index:
            raise ValueError("index size")
        isize, unpadded_size = _mbi(index)
        if not unpadded_size:
            raise ValueError("index record unpadded size")
        index = index[isize:]
        if not index:
            raise ValueError("index size")
        isize, uncompressed_size = _mbi(index)
        if not uncompressed_size:
            raise ValueError("index record uncompressed size")
        index = index[isize:]
        records.append((unpadded_size, uncompressed_size))

    block_start = size - 12 - backward_size
    blocks_len = sum((unpadded_size + 3) & ~3 for unpadded_size, _ in records)
    block_start -= blocks_len

    # Iterate over all blocks and add the correct block header CRC32
    for unpadded_size, _ in records:
        fh.seek(block_start)

        block_header = fh.read(1)
        block_header_size = (block_header[0] + 1) * 4
        block_header += fh.read(block_header_size - 1)
        repaired.add(fh.tell() - 4, _crc32(block_header[:-4]))

        block_start += (unpadded_size + 3) & ~3

    return repaired


def _mbi(data: bytes) -> tuple[int, int]:
    value = 0
    for size, byte in enumerate(data):
        value |= (byte & 0x7F) << (size * 7)
        if not byte & 0x80:
            return size + 1, value
    raise ValueError("Invalid mbi")


def _crc32(data: bytes) -> bytes:
    return int.to_bytes(crc32(data), 4, "little")


class ConfigNode(dict):
    def set(self, path: list[str], value: str) -> None:
        node = self

        for part in path[:-1]:
            if part not in node:
                node[part] = ConfigNode()
            node = node[part]

        node[path[-1]] = value

    def __getattr__(self, attr: str) -> ConfigNode | str:
        return self[attr]


class FortigateConfig(ConfigNode):
    @classmethod
    def from_fh(cls, fh: TextIO) -> FortigateConfig:
        root = cls()

        stack = []
        for parts in _parse_config(fh):
            cmd = parts[0]

            if cmd == "config":
                if parts[1] == "vdom" and stack == [["vdom"]]:
                    continue

                stack.append(parts[1:])

            elif cmd == "edit":
                stack.append(parts[1:])

            elif cmd == "end":
                stack.pop()

            elif cmd == "next":
                stack.pop()

            elif cmd == "set":
                path = []
                for part in stack:
                    path += part

                path.append(parts[1])
                root.set(path, parts[2:])

        return root


def _parse_config(fh: TextIO) -> Iterator[list[str]]:
    parts = []
    string = None

    for line in fh:
        if not (line := line.strip()) or line.startswith("#"):
            continue

        for part in line.split(" "):
            if part.startswith('"'):
                if part.endswith('"'):
                    parts.append(part[1:-1])
                else:
                    string = [part[1:]]
            elif part.endswith('"') and part[-2] != "\\":
                string.append(part[:-1])
                parts.append(" ".join(string))
                string = None
            elif string:
                string.append(part)
            else:
                parts.append(part)

        if string:
            string.append("\n")

        if parts and not string:
            yield parts
            parts = []
