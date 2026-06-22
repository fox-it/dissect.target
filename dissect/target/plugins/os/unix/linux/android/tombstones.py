from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import (
    TargetRecordDescriptor,
)
from dissect.target.plugin import OperatingSystem, Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


AndroidTombstonesRecord = TargetRecordDescriptor(
    "android/tombstone",
    [
        ("datetime", "ts"),
        ("string", "app_id"),
        ("command", "command"),
        ("varint", "pid"),
        ("varint", "tid"),
        ("varint", "pid"),
        ("varint", "signal_uid"),
        ("varint", "signal_pid"),
        ("varint", "process_uptime_seconds"),
        ("path", "source"),
    ],
)


class AndroidTombstonesPlugin(Plugin):
    """Android tombstones plugin."""

    def check_compatible(self) -> None:
        if self.target.os != OperatingSystem.ANDROID:
            raise UnsupportedPluginError("Target is not Android")

    @export(record=AndroidTombstonesRecord)
    def tombstones(self) -> Iterator[AndroidTombstonesRecord]:
        """Yield Android tombstone records.

        References:
            - https://source.android.com/docs/core/tests/debug
        """
        for path in self.target.fs.path("/").glob("*/tombstones/tombstone_*"):
            if path.suffix == ".pb":
                continue
            yield self.read_tombstone(path)

    def read_tombstone(self, path: Path) -> AndroidTombstonesRecord:
        """Read and parse a tombstone file."""
        timestamp = None
        app_id = None
        cmd_line = None
        process_uptime = None
        pid = None
        tid = None
        signal_uid = None
        signal_pid = None

        for i, line in enumerate(path.open("rt")):
            # Prevent reading too far into signal or backtrace as most
            # metadata is put in the first 10 lines of the tombstone.
            if i > 10:
                break

            if line.startswith("Timestamp: "):
                timestamp = parse_long_ms_ts(line.split(": ")[1].strip())
            if line.startswith("Process uptime: "):
                process_uptime = int(line.split(": ")[1].strip().replace("s", ""))
            if line.startswith("Cmdline: "):
                cmd_line = line.split(": ")[1].strip()
            if line.startswith("pid: "):
                parts = line.split(": ")
                pid = int(parts[1].split(",")[0])
                tid = int(parts[2].split(",")[0])
            if line.startswith("uid: "):
                signal_uid = int(line.split(": ")[-1].strip())
            if ">>>" in line and "<<<" in line:
                app_id = line.split(">>>")[1].split("<<<")[0].strip()
            if "from pid " in line:
                signal_pid = int(line.split("from pid ")[-1].split(",")[0].strip())

        if timestamp is None:
            stat = path.stat()
            timestamp = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

        return AndroidTombstonesRecord(
            ts=timestamp,
            app_id=app_id,
            pid=pid,
            tid=tid,
            signal_uid=signal_uid,
            signal_pid=signal_pid,
            command=cmd_line,
            process_uptime_seconds=process_uptime,
            source=path,
            _target=self.target,
        )


def parse_long_ms_ts(raw: str) -> datetime:
    """Parse a tombstone timestamp with 9-digit microseconds."""
    # Break `%Y-%m-%d %H:%M:%S.%f%z` in `%Y-%m-%d %H:%M:%S` and `%f%z`
    pre, _, suf = raw.partition(".")

    # microseconds can only be parsed up to 6 digits in python's datetime %f, so
    # we concat to the first 6 digits and append the %z value (e.g. `+0100`)
    # `%Y-%m-%d %H:%M:%S` + `.` + `%f` + `%z`
    ts = f"{pre}.{suf[0:6]}{suf[-5:]}"
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f%z").astimezone(tz=timezone.utc)
