from __future__ import annotations

from datetime import timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.log.helpers import RE_TS

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

SystemLogRecord = TargetRecordDescriptor(
    "macos/system_log",
    [("datetime", "ts"), ("string", "host"), ("string", "component"), ("string", "message"), ("path", "source")],
)


class SystemLogPlugin(Plugin):
    """Return system logs on macOS."""

    SYSTEM_LOG_GLOB = "/var/log/system.log*"

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_files = set()
        self._resolve_files()

    def check_compatible(self) -> None:
        if not self.log_files:
            raise UnsupportedPluginError("No system log files found.")

    def _resolve_files(self) -> None:
        for file in self.target.fs.glob(self.SYSTEM_LOG_GLOB):
            self.log_files.add(file)

    @export(record=SystemLogRecord)
    def system_log(self) -> Iterator[SystemLogRecord]:
        """Return all macOS system log messages."""
        for file in self.log_files:
            filepath = self.target.fs.path(file)

            current_buf = ""

            for ts, line in year_rollover_helper(filepath, RE_TS, "%b %d %H:%M:%S", timezone.utc):
                current_buf = line + "\n\t" + current_buf
                if ts:
                    match = RE_TS.match(current_buf)
                    asdf = current_buf[match.end() :].lstrip(" ")
                    hostname, component, message = asdf.split(" ", 2)

                    yield SystemLogRecord(
                        ts=ts,
                        host=hostname.strip(),
                        component=component.strip(),
                        message=message.strip(),
                        source=filepath,
                        _target=self.target,
                    )

                    current_buf = ""
