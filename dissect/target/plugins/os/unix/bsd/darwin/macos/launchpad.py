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


LaunchpadAppRecord = TargetRecordDescriptor(
    "macos/launchpad/apps",
    [
        ("datetime", "ts_modified"),
        ("string", "title"),
        ("string", "bundle_id"),
        ("string", "store_id"),
        ("string", "category"),
        ("string", "group_title"),
        ("varint", "ordering"),
        ("path", "source"),
    ],
)

LaunchpadGroupRecord = TargetRecordDescriptor(
    "macos/launchpad/groups",
    [
        ("string", "title"),
        ("varint", "item_id"),
        ("varint", "parent_id"),
        ("varint", "ordering"),
        ("varint", "group_type"),
        ("path", "source"),
    ],
)


class LaunchpadPlugin(Plugin):
    """Plugin to parse macOS Launchpad database.

    Parses the Launchpad app grid layout including apps, folders, and ordering.

    Location: /private/var/folders/<x>/<y>/0/com.apple.dock.launchpad/db/db
    """

    __namespace__ = "launchpad"

    LAUNCHPAD_GLOB = "private/var/folders/*/*/0/com.apple.dock.launchpad/db/db"

    def __init__(self, target):
        super().__init__(target)
        self._paths = list(self.target.fs.path("/").glob(self.LAUNCHPAD_GLOB))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No Launchpad database found")

    def _open_db(self, path):
        with path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        # Copy WAL and SHM if they exist
        for suffix in ["-wal", "-shm"]:
            src = path.parent.joinpath(path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    @export(record=LaunchpadAppRecord)
    def apps(self) -> Iterator[LaunchpadAppRecord]:
        """Parse Launchpad apps with bundle ID, category, folder, and grid position."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT a.title, a.bundleid, a.storeid, a.moddate,
                           a.category_id, i.ordering, i.parent_id,
                           c.uti AS category_uti,
                           g.title AS group_title
                    FROM apps a
                    JOIN items i ON a.item_id = i.rowid
                    LEFT JOIN categories c ON a.category_id = c.rowid
                    LEFT JOIN groups g ON i.parent_id = g.item_id
                    ORDER BY a.title
                """)
                for row in cursor:
                    yield LaunchpadAppRecord(
                        ts_modified=_cocoa_ts(row["moddate"]),
                        title=row["title"] or "",
                        bundle_id=row["bundleid"] or "",
                        store_id=row["storeid"] or "",
                        category=row["category_uti"] or "",
                        group_title=row["group_title"] or "",
                        ordering=row["ordering"] or 0,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing launchpad apps %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=LaunchpadGroupRecord)
    def groups(self) -> Iterator[LaunchpadGroupRecord]:
        """Parse Launchpad folders/groups."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT g.item_id, g.title,
                           i.parent_id, i.ordering, i.type
                    FROM groups g
                    JOIN items i ON g.item_id = i.rowid
                    ORDER BY i.ordering
                """)
                for row in cursor:
                    yield LaunchpadGroupRecord(
                        title=row["title"] or "",
                        item_id=row["item_id"] or 0,
                        parent_id=row["parent_id"] or 0,
                        ordering=row["ordering"] or 0,
                        group_type=row["type"] or 0,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing launchpad groups %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()
