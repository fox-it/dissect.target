from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ts(value):
    if value and value > 0:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


QuickLookRecord = TargetRecordDescriptor(
    "macos/quicklook/thumbnails",
    [
        ("datetime", "ts"),
        ("string", "file_path"),
        ("varint", "hit_count"),
        ("path", "source"),
    ],
)


class MacOSQuickLookPlugin(Plugin):
    """Plugin to parse macOS QuickLook thumbnail cache database.

    Tracks files that have had thumbnails generated for them.

    Locations:
        /private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/index.sqlite
        ~/Library/Caches/com.apple.QuickLook.ThumbnailsAgent/index.sqlite
    """

    __namespace__ = "quicklook"

    DB_GLOBS = [
        "private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/index.sqlite",
        "Users/*/Library/Caches/com.apple.QuickLook.ThumbnailsAgent/index.sqlite",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = []
        root = self.target.fs.path("/")
        for pattern in self.DB_GLOBS:
            self._db_paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No QuickLook thumbnail cache found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=QuickLookRecord)
    def thumbnails(self) -> Iterator[QuickLookRecord]:
        """Parse QuickLook thumbnail cache entries."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_thumbnails(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing QuickLook cache at %s: %s", db_path, e)

    def _parse_thumbnails(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()

            # Discover available tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r["name"] for r in cursor.fetchall()]

            # Try known table names
            target_table = None
            for candidate in ["thumbnails", "files", "thumbnail", "file"]:
                if candidate in tables:
                    target_table = candidate
                    break

            if not target_table:
                # Try first table that looks relevant
                for t in tables:
                    if "thumb" in t.lower() or "file" in t.lower():
                        target_table = t
                        break

            if not target_table and tables:
                target_table = tables[0]

            if not target_table:
                return

            cursor.execute(f"PRAGMA table_info([{target_table}])")
            columns = [col["name"] for col in cursor.fetchall()]

            if not columns:
                return

            cursor.execute(f"SELECT * FROM [{target_table}]")
            for row in cursor:
                # Try to find file path column
                file_path = ""
                for col in ["file_path", "path", "folder", "file_name", "filename", "name", "url"]:
                    try:
                        if col in columns and row[col] is not None:
                            file_path = str(row[col])
                            break
                    except (IndexError, KeyError):
                        continue

                # Try to find timestamp column
                ts = COCOA_EPOCH
                for col in ["last_hit_date", "hit_date", "date", "timestamp", "ts", "last_used_date", "creation_date"]:
                    try:
                        if col in columns and row[col] is not None:
                            ts = _cocoa_ts(float(row[col]))
                            break
                    except (IndexError, KeyError, TypeError, ValueError):
                        continue

                # Try to find hit count column
                hit_count = 0
                for col in ["hit_count", "hits", "count", "access_count"]:
                    try:
                        if col in columns and row[col] is not None:
                            hit_count = int(row[col])
                            break
                    except (IndexError, KeyError, TypeError, ValueError):
                        continue

                if file_path:
                    yield QuickLookRecord(
                        ts=ts,
                        file_path=file_path,
                        hit_count=hit_count,
                        source=db_path,
                        _target=self.target,
                    )
        finally:
            conn.close()
            tmp.close()
