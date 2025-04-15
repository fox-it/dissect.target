from __future__ import annotations

import io
import stat
import struct
import zipfile
import zlib
from typing import TYPE_CHECKING, BinaryIO

import defusedxml.ElementTree as ET
from dissect.util import ts

from dissect.target import filesystem
from dissect.target.helpers import fsutil, record, regutil
from dissect.target.loader import Loader
from dissect.target.plugin import OSPlugin, export
from dissect.target.plugins.os.windows.registry import RegistryPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path
    from xml.etree.ElementTree import Element

    from typing_extensions import Self

    from dissect.target.target import Target

EXTENSIONS = ("upr", "upf", "upr.zip", "upf.zip")

PATH_REPLACEMENTS = {
    r"%appdata%": "users/{user}/appdata/roaming",
    r"%localappdata%": "users/{user}/appdata/local",
    r"%localappdata%low": "users/{user}/appdata/locallow",
}


def find_pwr_dir(path: Path) -> Path | None:
    if not path.is_dir():
        return None

    pwr_dirs = [
        "Pwrmenu2",
        "PwrmenuPrd",
        "PwrmenuGAT",
    ]
    for p in pwr_dirs:
        pwrdir = path.joinpath(p)
        if not pwrdir.exists():
            continue

        userpref = pwrdir.joinpath("UserPref")
        if userpref.exists():
            for userpref_files in userpref.iterdir():
                if userpref_files.name.endswith(EXTENSIONS):
                    return pwrdir

                epath = userpref.joinpath(userpref_files)
                if epath.is_dir() and any(usrset_file.name.endswith(EXTENSIONS) for usrset_file in epath.iterdir()):
                    return pwrdir
    return None


class ResLoader(Loader):
    @staticmethod
    def detect(path: Path) -> bool:
        return find_pwr_dir(path) is not None

    def map(self, target: Target) -> None:
        path = find_pwr_dir(self.absolute_path)
        user_inf_path = path.joinpath("user.inf")

        vfs = filesystem.VirtualFilesystem(case_sensitive=False)
        target.filesystems.add(vfs)

        regflex = regutil.RegFlex()

        username = user_inf_path.read_text().strip() if user_inf_path.exists() else path.parts[-2]

        userpref = path.joinpath("UserPref")
        for fpath in userpref.rglob("*"):
            if not fpath.is_file():
                continue

            if fpath.suffix == ".zip":
                try:
                    zfile = zipfile.ZipFile(fpath, "r")
                except zipfile.BadZipFile:
                    pass

                fh = io.BytesIO(zfile.open(zfile.namelist()[0]).read())
            else:
                fh = fpath.open("rb")

            if "upr" in fpath.name:
                upr = UPR(fh)
                if upr.buf[:7] != b"RESZLIB":
                    continue
                regflex.map_definition(upr.open())

            if "upf" in fpath.name:
                try:
                    upf = UPF(fh)
                except Exception:
                    continue

                for fileobj in upf.files():
                    fpath = fileobj.path.replace("{user}", username)
                    fentry = ResFile(vfs, fpath, fileobj)
                    vfs.map_file_entry(fentry.path, fentry)

        target.props["username"] = username
        target._os_plugin = ResOSPlugin.create(target, vfs)
        target.add_plugin(RegistryPlugin, check_compatible=False)

        for name, hive in regflex.hives.items():
            path = name
            if name == "HKEY_CURRENT_USER":
                # name = 'S-0'
                path = "HKEY_USERS\\S-0"
            target.registry.add_hive(name, path, hive, fsutil.TargetPath(target.fs, "UPR"))


class ResFile(filesystem.VirtualFile):
    entry: File

    def __init__(self, fs: filesystem.VirtualFilesystem, path: str, entry: File, **kwargs):
        super().__init__(fs, path, entry)

    def stat(self) -> fsutil.stat_result:
        return fsutil.stat_result(
            [
                stat.S_IFREG,
                0,
                0,
                0,
                0,
                0,
                self.entry.size,
                ts.to_unix(self.entry.timestamps[2]),
                ts.to_unix(self.entry.timestamps[1]),
                ts.to_unix(self.entry.timestamps[0]),
            ]
        )

    def lstat(self) -> fsutil.stat_result:
        return self.stat()

    def open(self) -> BinaryIO:
        return self.entry.open()


class ResOSPlugin(OSPlugin):
    @classmethod
    def detect(cls, target: Target) -> bool:
        return True

    @classmethod
    def create(cls, target: Target, sysvol: filesystem.Filesystem) -> Self:
        target.fs.case_sensitive = False
        target.fs.mount("sysvol", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str:
        return self.target.props["username"]

    @export(property=True)
    def ips(self) -> list[str]:
        return []

    @export(property=True)
    def version(self) -> None:
        return None

    @export
    def users(self) -> Iterator[record.WindowsUserRecord]:
        yield record.WindowsUserRecord(
            sid="S-0",
            name=self.hostname,
            home=f"sysvol/users/{self.hostname}",
            _target=self.target,
        )

    @export(property=True)
    def os(self) -> str:
        return "windows"


class UPR:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.buf = fh.read()

    def open(self) -> io.StringIO:
        buf = self.buf
        if buf[:7] == b"RESZLIB":
            # Skip header
            buf = zlib.decompress(buf[11:])
        return io.StringIO(buf.decode("latin1"))


class UPF:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self._meta = self._read_metadata()
        self.metadata = ET.fromstring(self._meta)

        self._folders = {}
        self._files = {}

        self._parse()

    def folders(self) -> list[Folder]:
        return list(self._folders.values())

    def files(self) -> list[File]:
        return list(self._files.values())

    def _read_metadata(self) -> str:
        needle = b"R\x00E\x00S\x00Z\x00L\x00I\x00B\x00"

        if (offset := reverse_search(self.fh, needle)) == -1:
            raise ValueError("Invalid UPF file")

        # Skip header
        self.fh.seek(offset + 22)
        return zlib.decompress(self.fh.read()).decode("utf-16-le")

    def _parse(self) -> None:
        folders = self.metadata.find("folders")
        if folders is not None:
            for elem in folders.findall("folder"):
                self._iter_folder(elem)

        files = self.metadata.find("files")
        if files is not None:
            for elem in files:
                res_file = File(self, elem)
                self._files[res_file.guid] = res_file

    def _iter_folder(self, elem: Element, parent: Folder | None = None) -> None:
        folder = Folder(self, elem, parent=parent)
        self._folders[folder.guid] = folder

        for child in elem.findall("folder"):
            self._iter_folder(child, folder)


class File:
    def __init__(self, upf: UPF, elem: Element):
        self.upf = upf
        self.name = elem.find("name").text
        self.size = int(elem.find("filelen").text)
        self.offset = int(elem.find("offset").text)
        self.packed_size = int(elem.find("len").text)
        self.compressed = elem.find("compressed").text == "yes"

        timestamps = struct.unpack(">3Q", bytes.fromhex(elem.find("timestamp").text))
        self.timestamps = [ts.wintimestamp(t) for t in timestamps]

        self.guid = elem.get("guid")
        self.folder = self.upf._folders.get(elem.get("folderguid"), None)

    def __repr__(self) -> str:
        return f"<File path={self.path} size={self.size} timestamps={[str(t) for t in self.timestamps]}>"

    @property
    def path(self) -> str:
        if not self.folder:
            return self.name
        return f"{self.folder.path}/{self.name}"

    def open(self) -> io.BytesIO:
        fh = self.upf.fh
        offset = self.offset - 1
        if self.compressed:
            # Skip header
            fh.seek(offset + 11)
            buf = zlib.decompress(fh.read(self.packed_size))
        else:
            fh.seek(offset)
            buf = fh.read(self.packed_size)

        return io.BytesIO(buf)


class Folder:
    def __init__(self, upf: UPF, elem: Element, parent: Folder | None = None):
        self.upf = upf
        self.name = elem.find("name").text
        self.guid = elem.get("guid")
        self.parent = parent

    def __repr__(self) -> str:
        return f"<Folder path={self.path}>"

    @property
    def path(self) -> str:
        name = PATH_REPLACEMENTS.get(self.name.lower(), self.name)
        if self.parent:
            return f"{self.parent.path}/{name}"
        return name


def reverse_search(fh: BinaryIO, needle: bytes) -> int:
    BLOCK_SIZE = 1024 * 1024 * 64

    fh.seek(0, io.SEEK_END)
    size = fh.tell()
    offset = size

    while offset > 0:
        read_size = min(offset, BLOCK_SIZE)
        offset -= read_size

        fh.seek(offset)
        buf = fh.read(read_size)

        pos = buf.find(needle)
        if pos == -1:
            continue

        return offset + pos

    return -1
