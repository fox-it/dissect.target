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

ScreenTimeUsageRecord = TargetRecordDescriptor(
    "macos/screentime/usage",
    [
        ("datetime", "ts"),
        ("string", "bundle_identifier"),
        ("string", "web_domain"),
        ("float", "total_time"),
        ("varint", "number_of_pickups"),
        ("varint", "number_of_notifications"),
        ("string", "category"),
        ("path", "source"),
    ],
)

ScreenTimeBlockRecord = TargetRecordDescriptor(
    "macos/screentime/blocks",
    [
        ("datetime", "start_date"),
        ("datetime", "end_date"),
        ("string", "block_type"),
        ("varint", "number_of_blocks"),
        ("path", "source"),
    ],
)


class ScreenTimePlugin(Plugin):
    """Plugin to parse macOS ScreenTime databases.

    Parses app usage, screen time, and notification data from the
    ScreenTimeAgent RMAdminStore database.

    Location: /private/var/folders/*/*/0/com.apple.ScreenTimeAgent/
    """

    __namespace__ = "screentime"

    DB_GLOBS = [
        "private/var/folders/*/*/0/com.apple.ScreenTimeAgent/RMAdminStore-Local.sqlite",
        "private/var/folders/*/*/0/com.apple.ScreenTimeAgent/RMAdminStore-Cloud.sqlite",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = []
        for glob_pattern in self.DB_GLOBS:
            self._db_paths.extend(self.target.fs.path("/").glob(glob_pattern))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No ScreenTime database found")

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

    def _cocoa_to_dt(self, ts):
        if ts is not None and ts > 0:
            try:
                return COCOA_EPOCH + timedelta(seconds=ts)
            except (ValueError, OverflowError):
                pass
        return None

    def _table_exists(self, cursor, table_name):
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        return cursor.fetchone() is not None

    @export(record=ScreenTimeUsageRecord)
    def usage(self) -> Iterator[ScreenTimeUsageRecord]:
        """Parse ScreenTime app usage data."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_usage(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing ScreenTime usage at %s: %s", db_path, e)

    def _parse_usage(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            # Try known table names across macOS versions
            usage_tables = ["ZUSAGETIMEDITEM", "ZUSAGEBLOCK", "ZUSAGECATEGORY"]
            for table in usage_tables:
                if not self._table_exists(cursor, table):
                    continue
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [col["name"] for col in cursor.fetchall()]
                cursor.execute(f"SELECT * FROM {table}")
                for row in cursor:
                    ts = None
                    for ts_col in ["ZSTARTDATE", "ZTIMESTAMP", "ZCREATIONDATE", "ZLASTPICKUPDATE"]:
                        if ts_col in columns and row[ts_col]:
                            ts = self._cocoa_to_dt(row[ts_col])
                            break

                    bundle_id = ""
                    for bid_col in ["ZBUNDLEIDENTIFIER", "ZIDENTIFIER", "ZAPPBUNDLEIDENTIFIER"]:
                        if bid_col in columns and row[bid_col]:
                            bundle_id = str(row[bid_col])
                            break

                    yield ScreenTimeUsageRecord(
                        ts=ts,
                        bundle_identifier=bundle_id,
                        web_domain=str(row["ZDOMAIN"]) if "ZDOMAIN" in columns and row["ZDOMAIN"] else "",
                        total_time=float(row["ZTOTALTIME"]) if "ZTOTALTIME" in columns and row["ZTOTALTIME"] else 0.0,
                        number_of_pickups=row["ZNUMBEROFPICKUPS"]
                        if "ZNUMBEROFPICKUPS" in columns and row["ZNUMBEROFPICKUPS"]
                        else 0,
                        number_of_notifications=row["ZNUMBEROFNOTIFICATIONS"]
                        if "ZNUMBEROFNOTIFICATIONS" in columns and row["ZNUMBEROFNOTIFICATIONS"]
                        else 0,
                        category=str(row["ZCATEGORYTOKEN"])
                        if "ZCATEGORYTOKEN" in columns and row["ZCATEGORYTOKEN"]
                        else "",
                        source=db_path,
                        _target=self.target,
                    )
        finally:
            conn.close()
            tmp.close()

    @export(record=ScreenTimeBlockRecord)
    def blocks(self) -> Iterator[ScreenTimeBlockRecord]:
        """Parse ScreenTime usage blocks."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_blocks(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing ScreenTime blocks at %s: %s", db_path, e)

    def _parse_blocks(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            cursor = conn.cursor()
            if not self._table_exists(cursor, "ZUSAGEBLOCK"):
                return
            cursor.execute("PRAGMA table_info(ZUSAGEBLOCK)")
            columns = [col["name"] for col in cursor.fetchall()]
            cursor.execute("SELECT * FROM ZUSAGEBLOCK")
            for row in cursor:
                yield ScreenTimeBlockRecord(
                    start_date=self._cocoa_to_dt(row["ZSTARTDATE"])
                    if "ZSTARTDATE" in columns and row["ZSTARTDATE"]
                    else None,
                    end_date=self._cocoa_to_dt(row["ZENDDATE"]) if "ZENDDATE" in columns and row["ZENDDATE"] else None,
                    block_type=str(row["ZBLOCKCATEGORY"])
                    if "ZBLOCKCATEGORY" in columns and row["ZBLOCKCATEGORY"]
                    else "",
                    number_of_blocks=row["ZNUMBEROFBLOCKS"]
                    if "ZNUMBEROFBLOCKS" in columns and row["ZNUMBEROFBLOCKS"]
                    else 0,
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()
