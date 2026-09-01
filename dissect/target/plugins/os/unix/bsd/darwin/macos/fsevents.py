from __future__ import annotations

import contextlib
import gzip
import io
import struct
import zipfile
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


FSEventRecord = TargetRecordDescriptor(
    "macos/fsevents/entry",
    [
        ("string", "path"),
        ("varint", "event_id"),
        ("varint", "flags"),
        ("string", "flags_description"),
        ("varint", "node_id"),
        ("string", "source_file"),
        ("path", "source"),
    ],
)

# FSEvents flag definitions
# https://developer.apple.com/documentation/coreservices/1455361-fseventstreameventflags
FSEVENTS_FLAGS = {
    0x00000001: "Created",
    0x00000002: "Removed",
    0x00000004: "InodeMetaMod",
    0x00000008: "Renamed",
    0x00000010: "Modified",
    0x00000020: "FinderInfoMod",
    0x00000040: "ChangeOwner",
    0x00000080: "XattrMod",
    0x00000100: "IsFile",
    0x00000200: "IsDir",
    0x00000400: "IsSymlink",
    0x00000800: "IsLastHardlink",
    0x00001000: "IsHardlink",
    0x00004000: "Cloned",
    0x00010000: "EndOfTransaction",
    0x00020000: "Mount",
    0x00040000: "Unmount",
    0x00080000: "ItemCreated",
}

DLS1_MAGIC = b"1SLD"
DLS2_MAGIC = b"2SLD"
DLS3_MAGIC = b"3SLD"


def _decode_flags(flags):
    """Decode FSEvents flag bitmask to human-readable descriptions."""
    parts = []
    for bit, name in FSEVENTS_FLAGS.items():
        if flags & bit:
            parts.append(name)
    return "|".join(parts) if parts else f"0x{flags:08x}"


def _parse_fsevents_page(data, source_name):
    """Parse a single uncompressed FSEvents page (DLS1 or DLS2 format).

    Yields dicts with path, event_id, flags, node_id.
    """
    if len(data) < 12:
        return

    magic = data[:4]
    if magic == DLS3_MAGIC:
        version = 3
    elif magic == DLS2_MAGIC:
        version = 2
    elif magic == DLS1_MAGIC:
        version = 1
    else:
        return

    pos = 12  # skip header (magic + padding)

    while pos < len(data):
        # Read null-terminated path
        null_idx = data.find(b"\x00", pos)
        if null_idx == -1:
            break

        try:
            path = data[pos:null_idx].decode("utf-8", errors="replace")
        except Exception:
            break

        pos = null_idx + 1

        if version == 3:
            # DLS3: event_id (uint64) + flags (uint32) + node_id (uint64) + padding (uint32) = 24 bytes
            if pos + 24 > len(data):
                break
            event_id, flags, node_id = struct.unpack("<QIQ", data[pos : pos + 20])
            pos += 24
        elif version == 2:
            # DLS2: event_id (uint64) + flags (uint32) + node_id (uint64) = 20 bytes
            if pos + 20 > len(data):
                break
            event_id, flags, node_id = struct.unpack("<QIQ", data[pos : pos + 20])
            pos += 20
        else:
            # DLS1: event_id (uint64) + flags (uint32) = 12 bytes
            if pos + 12 > len(data):
                break
            event_id, flags = struct.unpack("<QI", data[pos : pos + 12])
            node_id = 0
            pos += 12

        yield {
            "path": path,
            "event_id": event_id,
            "flags": flags,
            "node_id": node_id,
            "source_file": source_name,
        }


def _read_fsevents_file(fh, source_name):
    """Read and decompress an FSEvents file, then parse all records."""
    raw = fh.read()

    # FSEvents files are gzip-compressed
    try:
        data = gzip.decompress(raw)
        yield from _parse_fsevents_page(data, source_name)
        return
    except Exception:
        pass

    # Velociraptor may zip-compress collected files
    if raw[:2] == b"PK":
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
            for name in zf.namelist():
                inner = zf.read(name)
                # Inner file may be gzip-compressed
                with contextlib.suppress(Exception):
                    inner = gzip.decompress(inner)
                yield from _parse_fsevents_page(inner, source_name)
            return
        except Exception:
            pass

    # May be uncompressed (older macOS or partial)
    yield from _parse_fsevents_page(raw, source_name)


class MacOSFSEventsPlugin(Plugin):
    """Plugin to parse macOS FSEvents (/.fseventsd/).

    FSEvents records file system changes: file/directory creation, deletion,
    renaming, metadata changes, and more. Each record includes the full path,
    an event ID, and flags describing the operation.

    Forensic value: proves file/directory existence and activity even after
    deletion. FSEvents persist across reboots and can contain historical
    records going back weeks or months.

    Locations:
        /.fseventsd/                    (boot volume)
        /private/var/db/fseventsd/      (live macOS, needs root)
        /System/Volumes/Data/.fseventsd/ (APFS data volume)
    """

    __namespace__ = "fsevents"

    FSEVENTS_PATHS = [
        ".fseventsd",
        "%2Efseventsd",
        "private/var/db/fseventsd",
        "System/Volumes/Data/.fseventsd",
        "System/Volumes/Data/%2Efseventsd",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._files = []
        for base in self.FSEVENTS_PATHS:
            fseventsd = self.target.fs.path("/").joinpath(base)
            try:
                if not fseventsd.exists() or not fseventsd.is_dir():
                    continue
                for entry in fseventsd.iterdir():
                    name = entry.name
                    # Skip uuid file and non-hex-named files
                    if name.startswith("fseventsd-") or name.startswith("."):
                        continue
                    if entry.is_file():
                        self._files.append(entry)
            except PermissionError:
                continue
        self._files.sort(key=lambda p: p.name)

    def check_compatible(self) -> None:
        if not self._files:
            raise UnsupportedPluginError("No FSEvents files found")

    @export(record=FSEventRecord)
    def events(self) -> Iterator[FSEventRecord]:
        """Parse all FSEvents records showing file system activity."""
        for fpath in self._files:
            try:
                with fpath.open("rb") as fh:
                    for rec in _read_fsevents_file(fh, fpath.name):
                        yield FSEventRecord(
                            path=rec["path"],
                            event_id=rec["event_id"],
                            flags=rec["flags"],
                            flags_description=_decode_flags(rec["flags"]),
                            node_id=rec["node_id"],
                            source_file=rec["source_file"],
                            source=fpath,
                            _target=self.target,
                        )
            except Exception as e:
                self.target.log.warning("Error parsing FSEvents file %s: %s", fpath, e)
