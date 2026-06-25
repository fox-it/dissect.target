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


def _format_duration(value):
    """Format duration as seconds string."""
    if value is None:
        return "0"
    return str(round(value, 2))


CallRecord = TargetRecordDescriptor(
    "macos/callhistory/calls",
    [
        ("datetime", "ts"),
        ("string", "address"),
        ("string", "name"),
        ("varint", "call_type"),
        ("boolean", "answered"),
        ("boolean", "originated"),
        ("string", "duration"),
        ("varint", "disconnected_cause"),
        ("string", "iso_country_code"),
        ("string", "location"),
        ("string", "service_provider"),
        ("string", "unique_id"),
        ("path", "source"),
    ],
)


class CallHistoryPlugin(Plugin):
    """Plugin to parse macOS Call History database.

    Parses call records from the CallHistory.storedata SQLite database
    including phone calls, FaceTime, and third-party VoIP calls.

    Location: ~/Library/Application Support/CallHistoryDB/CallHistory.storedata
    """

    __namespace__ = "callhistory"

    DB_GLOB = "Users/*/Library/Application Support/CallHistoryDB/CallHistory.storedata"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No CallHistory.storedata found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        # Copy WAL and SHM if they exist
        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    # ── Calls ───────────────────────────────────────────────────────────

    @export(record=CallRecord)
    def calls(self) -> Iterator[CallRecord]:
        """Parse call records from CallHistory.storedata."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_calls(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing call history at %s: %s", db_path, e)

    def _parse_calls(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ZDATE, ZDURATION, ZADDRESS, ZNAME, ZCALLTYPE,
                       ZANSWERED, ZORIGINATED, ZDISCONNECTED_CAUSE,
                       ZISO_COUNTRY_CODE, ZLOCATION, ZSERVICE_PROVIDER,
                       ZUNIQUE_ID
                FROM ZCALLRECORD
                ORDER BY ZDATE DESC
            """)
            for row in cursor:
                yield CallRecord(
                    ts=_cocoa_ts(row["ZDATE"]),
                    address=row["ZADDRESS"] or "",
                    name=row["ZNAME"] or "",
                    call_type=row["ZCALLTYPE"] or 0,
                    answered=bool(row["ZANSWERED"]),
                    originated=bool(row["ZORIGINATED"]),
                    duration=_format_duration(row["ZDURATION"]),
                    disconnected_cause=row["ZDISCONNECTED_CAUSE"] or 0,
                    iso_country_code=row["ZISO_COUNTRY_CODE"] or "",
                    location=row["ZLOCATION"] or "",
                    service_provider=row["ZSERVICE_PROVIDER"] or "",
                    unique_id=row["ZUNIQUE_ID"] or "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
