from __future__ import annotations

import contextlib
import io
import zipfile
from typing import TYPE_CHECKING, BinaryIO

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

cs = cstruct(endian="<")

cs.load("""
struct fsevent_v1 {
    uint64 event_id;
    uint32 flags;
};

struct fsevent_v2 {
    uint64 event_id;
    uint32 flags;
    uint64 node_id;
};

struct fsevent_v3 {
    uint64 event_id;
    uint32 flags;
    uint64 node_id;
    uint32 padding;
};
""")

FSEventRecord = TargetRecordDescriptor(
    "macos/fsevents/entry",
    [
        ("string", "path"),
        ("varint", "event_id"),
        ("string[]", "event_flags"),
        ("varint", "node_id"),
        ("path", "source"),
    ],
)

# FSEvents flag definitions
# TODO: Verify that these flag definitions are correct
# And look into missing definitions (eg. 0x00800000)
FSEVENTS_FLAGS = {
    0x00000001: "MustScanSubDirs",
    0x00000002: "UserDropped",
    0x00000004: "KernelDropped",
    0x00000008: "EventIdsWrapped",
    0x00000010: "HistoryDone",
    0x00000020: "RootChanged",
    0x00000040: "Mount",
    0x00000080: "Unmount",
    0x00000100: "ItemCreated",
    0x00000200: "ItemRemoved",
    0x00000400: "InodeMetaMod",
    0x00000800: "ItemRenamed",
    0x00001000: "ItemModified",
    0x00002000: "ItemFinderInfoMod",
    0x00004000: "ItemChangeOwner",
    0x00008000: "ItemXattrMod",
    0x00010000: "ItemIsFile",
    0x00020000: "ItemIsDir",
    0x00040000: "ItemIsSymlink",
    0x00080000: "OwnEvent",
    0x00100000: "ItemIsHardlink",
    0x00200000: "ItemIsLastHardlink",
    0x00400000: "ItemCloned",
}

DLS1_MAGIC = b"1SLD"
DLS2_MAGIC = b"2SLD"
DLS3_MAGIC = b"3SLD"


def _decode_flags(flags: int) -> list[str] | None:
    """Decode FSEvents flag bitmask to a list of human-readable descriptions."""
    if flags == 0:
        return None

    parts = []
    known_mask = 0

    for bit, name in FSEVENTS_FLAGS.items():
        if flags & bit:
            parts.append(name)
        known_mask |= bit

    # detect unknown bits
    unknown = flags & ~known_mask

    if unknown:
        # If flags contain bits outside the defined mask, add unknown flag
        parts.append(f"Unknown(0x{unknown:08x})")

    return parts


def _parse_fsevents_page(data: bytes) -> Iterator[dict]:
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
            rec = cs.fsevent_v3(data[pos : pos + 24])
            event_id = rec.event_id
            flags = rec.flags
            node_id = rec.node_id
            pos += 24
        elif version == 2:
            # DLS2: event_id (uint64) + flags (uint32) + node_id (uint64) = 20 bytes
            if pos + 20 > len(data):
                break
            rec = cs.fsevent_v2(data[pos : pos + 20])
            event_id = rec.event_id
            flags = rec.flags
            node_id = rec.node_id
            pos += 20
        else:
            # DLS1: event_id (uint64) + flags (uint32) = 12 bytes
            if pos + 12 > len(data):
                break

            rec = cs.fsevent_v1(data[pos : pos + 12])
            event_id = rec.event_id
            flags = rec.flags
            node_id = 0
            pos += 12

        yield {
            "path": path,
            "event_id": event_id,
            "flags": flags,
            "node_id": node_id,
        }


def _parse_fsevents_stream(data: bytes) -> Iterator[dict]:
    pos = 0
    length = len(data)

    while pos < length:
        if data[pos : pos + 4] not in (DLS1_MAGIC, DLS2_MAGIC, DLS3_MAGIC):
            pos += 1
            continue

        start = pos
        pos += 12

        # find next header
        next_pos = pos
        while next_pos < length:
            if data[next_pos : next_pos + 4] in (DLS1_MAGIC, DLS2_MAGIC, DLS3_MAGIC):
                break
            next_pos += 1

        page = data[start:next_pos]

        yield from _parse_fsevents_page(page)

        pos = next_pos


def _read_fsevents_file(fh: BinaryIO) -> Iterator[dict]:
    """Read and decompress an FSEvents file, then parse all records."""
    raw = fh.read()

    # FSEvents files are gzip-compressed
    try:
        bio = io.BytesIO(raw)
        data = open_decompress(fileobj=bio).read()
        yield from _parse_fsevents_stream(data)
    except Exception:
        pass
    else:
        return

    # Velociraptor may zip-compress collected files
    if raw[:2] == b"PK":
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
            for name in zf.namelist():
                inner = zf.read(name)
                # Inner file may be gzip-compressed
                with contextlib.suppress(Exception):
                    bio = io.BytesIO(inner)
                    inner = open_decompress(fileobj=bio).read()
                yield from _parse_fsevents_page(inner)
        except Exception:
            pass
        else:
            return

    # May be uncompressed (older macOS or partial)
    yield from _parse_fsevents_page(raw)


class FSEventsPlugin(Plugin):
    """Plugin to parse macOS FSEvents (File System Events).

    FFSEvents is a macOS API that allows applications to register for notifications of
    changes like file creation, deletion, modification, and renaming to a given directory tree
    which helps applications to keep track of file system changes in real-time without continuously
    scanning the disk.

    Forensic value: FSEvents capture detailed information about modifications occurring within
    the file system such as file creation, deletion, modification, renaming and mounting. offering
    a timeline of changes that can help identify patterns or anomalies, and can uncover critical
    artifacts that play a key role in cross-referencing and validating other digital evidence during investigations.

    References:
        - https://developer.apple.com/documentation/coreservices/1455361-fseventstreameventflags
        - https://hackmd.io/@M4shl3/FSEvents
    """

    PATHS = (
        ".fseventsd/fc*",
        "%2Efseventsd/fc*",
        "/var/db/fseventsd/fc*",
        "System/Volumes/Data/.fseventsd/fc*",
        "System/Volumes/Data/%2Efseventsd/fc*",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def _find_files(self) -> set:
        files = set()

        for pattern in self.PATHS:
            for path in self.target.fs.glob(pattern):
                files.add(self.target.fs.path(path))

        return files

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError("No FSEvents files found")

    @export(record=FSEventRecord)
    def fs_events(self) -> Iterator[FSEventRecord]:
        """Parse all FSEvents records showing file system activity.

        Yields FSEventRecords with the following fields:

        .. code-block:: text

            path (string): Path to the affected file or directory.
            event_id (varint): Identifier for the event.
            flags (string[]): Event flag names decoded from bitmask.
            node_id (varint): File system node identifier.
            source (path): Path to the fs events file.
        """
        for file in self.files:
            with file.open("rb") as fh:
                for rec in _read_fsevents_file(fh):
                    yield FSEventRecord(
                        path=rec["path"],
                        event_id=rec["event_id"],
                        event_flags=_decode_flags(rec["flags"]),
                        node_id=rec["node_id"],
                        source=file,
                        _target=self.target,
                    )
