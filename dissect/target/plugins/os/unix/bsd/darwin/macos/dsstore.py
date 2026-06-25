from __future__ import annotations

import contextlib
import struct
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


DSStoreRecord = TargetRecordDescriptor(
    "macos/dsstore/entry",
    [
        ("string", "filename"),
        ("string", "attribute"),
        ("string", "attr_type"),
        ("string", "value"),
        ("string", "directory"),
        ("path", "source"),
    ],
)

DSStoreFileRecord = TargetRecordDescriptor(
    "macos/dsstore/file",
    [
        ("string", "directory"),
        ("varint", "entry_count"),
        ("varint", "size_bytes"),
        ("string", "filenames_seen"),
        ("path", "source"),
    ],
)


def _parse_ds_store_data(data):
    """Parse a .DS_Store binary file and yield record dicts."""
    if len(data) < 36 or data[4:8] != b"Bud1":
        return

    records = []
    pos = 0x20

    while pos < len(data) - 12:
        name_len = struct.unpack(">I", data[pos : pos + 4])[0]

        if name_len == 0 or name_len > 512 or pos + 4 + name_len * 2 + 8 > len(data):
            pos += 1
            continue

        name_bytes = data[pos + 4 : pos + 4 + name_len * 2]
        try:
            name = name_bytes.decode("utf-16-be")
        except Exception:
            pos += 1
            continue

        if not name or not all(c.isprintable() or c in "\t\n" for c in name):
            pos += 1
            continue

        attr_pos = pos + 4 + name_len * 2
        if attr_pos + 8 > len(data):
            pos += 1
            continue

        struct_id = data[attr_pos : attr_pos + 4]
        type_code = data[attr_pos + 4 : attr_pos + 8]

        try:
            sid = struct_id.decode("ascii")
            tc = type_code.decode("ascii")
        except Exception:
            pos += 1
            continue

        if not all(c.isalnum() or c in "_" for c in sid):
            pos += 1
            continue

        val_pos = attr_pos + 8
        value = ""

        if tc == "bool":
            if val_pos + 1 <= len(data):
                value = str(bool(data[val_pos]))
                val_pos += 1
        elif tc == "long" or tc == "shor":
            if val_pos + 4 <= len(data):
                value = str(struct.unpack(">I", data[val_pos : val_pos + 4])[0])
                val_pos += 4
        elif tc == "blob":
            if val_pos + 4 <= len(data):
                blob_len = struct.unpack(">I", data[val_pos : val_pos + 4])[0]
                if blob_len < 65536 and val_pos + 4 + blob_len <= len(data):
                    value = f"<{blob_len} bytes>"
                    val_pos += 4 + blob_len
        elif tc == "ustr":
            if val_pos + 4 <= len(data):
                ustr_len = struct.unpack(">I", data[val_pos : val_pos + 4])[0]
                if ustr_len < 1000 and val_pos + 4 + ustr_len * 2 <= len(data):
                    with contextlib.suppress(Exception):
                        value = data[val_pos + 4 : val_pos + 4 + ustr_len * 2].decode("utf-16-be")
                    val_pos += 4 + ustr_len * 2
        elif tc == "dutc":
            if val_pos + 8 <= len(data):
                ts_val = struct.unpack(">Q", data[val_pos : val_pos + 8])[0]
                from datetime import datetime, timedelta, timezone

                hfs_epoch = datetime(1904, 1, 1, tzinfo=timezone.utc)
                try:
                    value = str(hfs_epoch + timedelta(seconds=ts_val / 65536))
                except Exception:
                    value = str(ts_val)
                val_pos += 8
        elif tc == "comp":
            if val_pos + 8 <= len(data):
                value = str(struct.unpack(">q", data[val_pos : val_pos + 8])[0])
                val_pos += 8
        elif tc == "type" and val_pos + 4 <= len(data):
            value = data[val_pos : val_pos + 4].decode("ascii", errors="replace")
            val_pos += 4

        records.append(
            {
                "filename": name,
                "attribute": sid,
                "type": tc,
                "value": value,
            }
        )

        pos = val_pos if val_pos > pos + 4 else pos + 1

    return records


class MacOSDSStorePlugin(Plugin):
    """Plugin to parse macOS .DS_Store files.

    .DS_Store files are created by Finder in every directory visited.
    They reveal directory contents and Finder view settings, which is
    forensically valuable for proving directory access and file existence.

    Locations: everywhere — scanned recursively under /Users/ and /
    """

    __namespace__ = "dsstore"

    DSSTORE_DIRS = [
        "Users/*/",
        "Users/*/.Trash/",
        "Users/*/Desktop/",
        "Users/*/Documents/",
        "Users/*/Downloads/",
        "Users/*/Library/",
        "Users/*/Library/Application Support/",
        "Users/*/Library/CloudStorage/",
        "Users/*/Library/Mobile Documents/.Trash/",
        "Users/*/Applications/",
    ]

    DSSTORE_NAMES = {".DS_Store", "%2EDS_Store"}

    def __init__(self, target):
        super().__init__(target)
        self._ds_paths = set()
        root = self.target.fs.path("/")
        for pattern in self.DSSTORE_DIRS:
            for parent in root.glob(pattern):
                try:
                    for child in parent.iterdir():
                        if child.name in self.DSSTORE_NAMES and child.is_file():
                            self._ds_paths.add(child)
                except (PermissionError, OSError):
                    continue
        self._ds_paths = sorted(self._ds_paths)

    def check_compatible(self) -> None:
        if not self._ds_paths:
            raise UnsupportedPluginError("No .DS_Store files found")

    # ── List DS_Store files ──────────────────────────────────────────────

    @export(record=DSStoreFileRecord)
    def files(self) -> Iterator[DSStoreFileRecord]:
        """List all .DS_Store files with entry counts and referenced filenames."""
        for ds_path in self._ds_paths:
            try:
                with ds_path.open("rb") as fh:
                    data = fh.read()
                records = _parse_ds_store_data(data)
                filenames = sorted({r["filename"] for r in records})

                yield DSStoreFileRecord(
                    directory=str(ds_path.parent),
                    entry_count=len(records),
                    size_bytes=len(data),
                    filenames_seen=", ".join(filenames),
                    source=ds_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error reading %s: %s", ds_path, e)

    # ── All entries ──────────────────────────────────────────────────────

    @export(record=DSStoreRecord)
    def entries(self) -> Iterator[DSStoreRecord]:
        """Parse all .DS_Store entries showing files/folders that existed in each directory."""
        for ds_path in self._ds_paths:
            try:
                with ds_path.open("rb") as fh:
                    data = fh.read()
                records = _parse_ds_store_data(data)
                directory = str(ds_path.parent)

                for rec in records:
                    yield DSStoreRecord(
                        filename=rec["filename"],
                        attribute=rec["attribute"],
                        attr_type=rec["type"],
                        value=rec["value"],
                        directory=directory,
                        source=ds_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", ds_path, e)
