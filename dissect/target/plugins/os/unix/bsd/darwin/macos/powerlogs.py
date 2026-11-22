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
    """Convert Cocoa timestamp (seconds since 2001-01-01) to datetime."""
    if value and value > 0:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


SleepWakeRecord = TargetRecordDescriptor(
    "macos/powerlogs/sleep_wake",
    [
        ("datetime", "ts"),
        ("string", "power_state"),
        ("path", "source"),
    ],
)

AppUsageRecord = TargetRecordDescriptor(
    "macos/powerlogs/app_usage",
    [
        ("datetime", "ts"),
        ("string", "bundle_id"),
        ("path", "source"),
    ],
)

NetworkRecord = TargetRecordDescriptor(
    "macos/powerlogs/network",
    [
        ("datetime", "ts"),
        ("path", "source"),
    ],
)


class PowerLogsPlugin(Plugin):
    """Plugin to parse macOS powerlog database.

    Parses sleep/wake events, application usage, and network activity from
    the CurrentPowerlog.PLSQL database. This database has 250+ tables and
    schemas vary by macOS version.

    Location: /private/var/db/powerlog/CurrentPowerlog.PLSQL
    """

    __namespace__ = "powerlogs"

    DB_GLOB = "private/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No CurrentPowerlog.PLSQL found")

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

    def _get_columns(self, conn, table_name):
        """Discover columns for a table using PRAGMA table_info."""
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        return [col["name"] for col in cursor.fetchall()]

    def _table_exists(self, conn, table_name):
        """Check if a table exists in the database."""
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        return cursor.fetchone() is not None

    @export(record=SleepWakeRecord)
    def sleep_wake(self) -> Iterator[SleepWakeRecord]:
        """Parse sleep/wake power state events from the powerlog database."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_sleep_wake(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing powerlogs sleep_wake at %s: %s", db_path, e)

    def _parse_sleep_wake(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            if not self._table_exists(conn, "PLSleepWakeAgent_EventForward_PowerState"):
                return

            columns = self._get_columns(conn, "PLSleepWakeAgent_EventForward_PowerState")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM PLSleepWakeAgent_EventForward_PowerState")
            for row in cursor:
                try:
                    ts_val = row["timestamp"] if "timestamp" in columns else None
                except (IndexError, KeyError):
                    ts_val = None

                try:
                    power_state = str(row["PowerState"]) if "PowerState" in columns else ""
                except (IndexError, KeyError):
                    power_state = ""

                yield SleepWakeRecord(
                    ts=_cocoa_ts(ts_val),
                    power_state=power_state if power_state != "None" else "",
                    source=db_path,
                    _target=self.target,
                )
        finally:
            conn.close()
            tmp.close()

    @export(record=AppUsageRecord)
    def app_usage(self) -> Iterator[AppUsageRecord]:
        """Parse application usage events from the powerlog database."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_app_usage(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing powerlogs app_usage at %s: %s", db_path, e)

    def _parse_app_usage(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            table_name = "PLApplicationAgent_EventForward_Application"
            if not self._table_exists(conn, table_name):
                return

            columns = self._get_columns(conn, table_name)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            for row in cursor:
                try:
                    ts_val = row["timestamp"] if "timestamp" in columns else None
                except (IndexError, KeyError):
                    ts_val = None

                try:
                    bundle_id = str(row["BundleID"]) if "BundleID" in columns else ""
                except (IndexError, KeyError):
                    bundle_id = ""

                yield AppUsageRecord(
                    ts=_cocoa_ts(ts_val),
                    bundle_id=bundle_id if bundle_id != "None" else "",
                    source=db_path,
                    _target=self.target,
                )
        except Exception as e:
            self.target.log.warning("Error querying app_usage table at %s: %s", db_path, e)
        finally:
            conn.close()
            tmp.close()

    @export(record=NetworkRecord)
    def network(self) -> Iterator[NetworkRecord]:
        """Parse cumulative network usage events from the powerlog database."""
        for db_path in self._db_paths:
            try:
                yield from self._parse_network(db_path)
            except Exception as e:
                self.target.log.warning("Error parsing powerlogs network at %s: %s", db_path, e)

    def _parse_network(self, db_path):
        conn, tmp = self._open_db(db_path)
        try:
            table_name = "PLNetworkAgent_EventBackward_CumulativeNetworkUsage"
            if not self._table_exists(conn, table_name):
                return

            columns = self._get_columns(conn, table_name)
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            for row in cursor:
                try:
                    ts_val = row["timestamp"] if "timestamp" in columns else None
                except (IndexError, KeyError):
                    ts_val = None

                yield NetworkRecord(
                    ts=_cocoa_ts(ts_val),
                    source=db_path,
                    _target=self.target,
                )
        except Exception as e:
            self.target.log.warning("Error querying network table at %s: %s", db_path, e)
        finally:
            conn.close()
            tmp.close()
