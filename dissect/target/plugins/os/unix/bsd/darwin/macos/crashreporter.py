from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


CrashReporterRecord = TargetRecordDescriptor(
    "macos/crashreporter/entries",
    [
        ("string", "app_name"),
        ("string", "bundle_id"),
        ("string", "record_type"),
        ("string", "build_version"),
        ("string", "short_version"),
        ("varint", "active_seconds"),
        ("varint", "foreground_seconds"),
        ("varint", "launches"),
        ("varint", "counter_3"),
        ("varint", "counter_4"),
        ("varint", "counter_5"),
        ("varint", "counter_6"),
        ("varint", "counter_7"),
        ("string", "store_id_1"),
        ("string", "store_id_2"),
        ("string", "os_build"),
        ("path", "source"),
    ],
)

CrashReporterEventRecord = TargetRecordDescriptor(
    "macos/crashreporter/events",
    [
        ("datetime", "ts"),
        ("string", "app_name"),
        ("string", "event_type"),
        ("path", "source"),
    ],
)


class CrashReporterPlugin(Plugin):
    """Plugin to parse macOS CrashReporter plists.

    Parses crash reporter data from:
    ~/Library/Application Support/CrashReporter/*.plist

    Two types of plists exist:
    - Simple: contain a ForceQuitDate or Date key (crash/force-quit timestamp)
    - Rich (Intervals): contain appRecords with usage counters, crash stats,
      and app metadata per application
    """

    __namespace__ = "crashreporter"

    CRASHREPORTER_GLOB = "Users/*/Library/Application Support/CrashReporter/*.plist"

    def __init__(self, target):
        super().__init__(target)
        self._paths = list(self.target.fs.path("/").glob(self.CRASHREPORTER_GLOB))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No CrashReporter plist files found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    def _app_name_from_filename(self, path):
        """Extract app name from plist filename (e.g. 'Brave Browser_C50DD1FE-...' -> 'Brave Browser')."""
        name = str(path).rsplit("/", 1)[-1]
        if "_" in name:
            name = name.rsplit(".plist", 1)[0]
            name = name.split("_")[0]
        return name

    @export(record=CrashReporterRecord)
    def entries(self) -> Iterator[CrashReporterRecord]:
        """Parse CrashReporter Intervals plist for per-app usage and crash statistics."""
        for path in self._paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                if "appRecords" not in data:
                    continue

                os_build = data.get("OSBuild", "")

                for rec in data.get("appRecords", []):
                    if len(rec) < 13:
                        continue

                    yield CrashReporterRecord(
                        app_name=str(rec[1]),
                        bundle_id=str(rec[2]),
                        record_type=str(rec[0]),
                        build_version=str(rec[3]),
                        short_version=str(rec[4]),
                        active_seconds=rec[5],
                        foreground_seconds=rec[6],
                        launches=rec[7],
                        counter_3=rec[8],
                        counter_4=rec[9],
                        counter_5=rec[10],
                        counter_6=rec[11],
                        counter_7=rec[12],
                        store_id_1=str(rec[13]) if len(rec) > 13 else "",
                        store_id_2=str(rec[14]) if len(rec) > 14 else "",
                        os_build=os_build,
                        source=path,
                        _target=self.target,
                    )

                for rec in data.get("appRecords_lastMas", []):
                    if len(rec) < 13:
                        continue

                    yield CrashReporterRecord(
                        app_name=str(rec[1]),
                        bundle_id=str(rec[2]),
                        record_type=str(rec[0]),
                        build_version=str(rec[3]),
                        short_version=str(rec[4]),
                        active_seconds=rec[5],
                        foreground_seconds=rec[6],
                        launches=rec[7],
                        counter_3=rec[8],
                        counter_4=rec[9],
                        counter_5=rec[10],
                        counter_6=rec[11],
                        counter_7=rec[12],
                        store_id_1=str(rec[13]) if len(rec) > 13 else "",
                        store_id_2=str(rec[14]) if len(rec) > 14 else "",
                        os_build=os_build,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)

    @export(record=CrashReporterEventRecord)
    def events(self) -> Iterator[CrashReporterEventRecord]:
        """Parse CrashReporter plists for crash and force-quit timestamps."""
        for path in self._paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                app_name = self._app_name_from_filename(path)

                for key, event_type in [
                    ("ForceQuitDate", "force_quit"),
                    ("Date", "crash"),
                ]:
                    ts = data.get(key)
                    if ts is None:
                        continue

                    if isinstance(ts, datetime):
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                    else:
                        continue

                    yield CrashReporterEventRecord(
                        ts=ts,
                        app_name=app_name,
                        event_type=event_type,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)
