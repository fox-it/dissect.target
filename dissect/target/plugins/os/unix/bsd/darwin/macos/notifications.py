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


# Cocoa epoch: seconds since 2001-01-01
COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ts(value):
    if value and value > 0:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


NotificationAppRecord = TargetRecordDescriptor(
    "macos/notifications/apps",
    [
        ("varint", "app_id"),
        ("string", "bundle_id"),
        ("varint", "badge"),
        ("path", "source"),
    ],
)

NotificationEntryRecord = TargetRecordDescriptor(
    "macos/notifications/entries",
    [
        ("datetime", "ts_request"),
        ("datetime", "ts_delivered"),
        ("string", "bundle_id"),
        ("boolean", "presented"),
        ("varint", "style"),
        ("path", "source"),
    ],
)


class NotificationsPlugin(Plugin):
    """Plugin to parse macOS User Notifications database (db2/db).

    Parses notification metadata from the usernoted database including
    app registrations and notification delivery records.

    Location:
    - ~/Library/Group Containers/group.com.apple.usernoted/db2/db
    """

    __namespace__ = "notifications"

    DB_GLOB = "Users/*/Library/Group Containers/group.com.apple.usernoted/db2/db"

    def __init__(self, target):
        super().__init__(target)
        self._paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No usernoted notification database found")

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

    @export(record=NotificationAppRecord)
    def apps(self) -> Iterator[NotificationAppRecord]:
        """Parse registered notification apps from usernoted db."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT app_id, identifier, badge
                    FROM app
                """)
                for row in cursor:
                    yield NotificationAppRecord(
                        app_id=row["app_id"] or 0,
                        bundle_id=row["identifier"] or "",
                        badge=row["badge"] or 0,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing notification apps %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()

    @export(record=NotificationEntryRecord)
    def entries(self) -> Iterator[NotificationEntryRecord]:
        """Parse notification entries from usernoted db."""
        for path in self._paths:
            try:
                conn, tmp = self._open_db(path)
            except Exception as e:
                self.target.log.warning("Error opening %s: %s", path, e)
                continue

            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT r.request_date, r.delivered_date,
                           r.presented, r.style,
                           a.identifier
                    FROM record r
                    LEFT JOIN app a ON r.app_id = a.app_id
                    ORDER BY r.request_date DESC
                """)
                for row in cursor:
                    yield NotificationEntryRecord(
                        ts_request=_cocoa_ts(row["request_date"]),
                        ts_delivered=_cocoa_ts(row["delivered_date"]),
                        bundle_id=row["identifier"] or "",
                        presented=bool(row["presented"]),
                        style=row["style"] or 0,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing notification entries %s: %s", path, e)
            finally:
                conn.close()
                tmp.close()
