from __future__ import annotations

import gzip
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import tzinfo

    from dissect.target.target import Target

macOSSystemLogRecord = TargetRecordDescriptor(
    "macos/system",
    [("datetime", "ts"), ("string", "host"), ("string", "component"), ("string", "message"), ("path", "source")],
)

RE_TIMESTAMP_PATTERN = re.compile(r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")


class SystemLogPlugin(Plugin):
    """Return information related software installations and updates on macOS.

    References:
        - https://sansorg.egnyte.com/dl/m9ftGF7heI
    """

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

    @export(record=macOSSystemLogRecord)
    def systemlog(self) -> Iterator[macOSSystemLogRecord]:
        """Return all macOS install log messages.

        Yields macOSSystemLogRecord instances with fields:

        .. code-block:: text

            ts (datetime): Timestamp of the log line.
            host (str): Hostname.
            component (str): Component name.
            message (str): Log message.

        References:
            - https://sansorg.egnyte.com/dl/m9ftGF7heI
        """
        for file in self.log_files:
            filepath = self.target.fs.path(file)

            logfile = gzip.open(filepath, mode="rt") if file.endswith(".gz") else filepath.open(mode="rt")  # noqa: SIM115

            current_ts: re.Match[str] | None = None
            current_buf = ""

            for line in logfile.readlines():
                # If we have a buffer with a timestamp and
                # our current line also has a timestamp,
                # we should have a complete record in our buffer.
                if ts_match := RE_TIMESTAMP_PATTERN.match(line):
                    if current_ts:
                        # Add 1 to skip the whitespace after the timestamp.
                        asdf = current_buf[len(current_ts.group()) + 1 :]
                        hostname, component, message = asdf.split(" ", 2)

                        yield macOSSystemLogRecord(
                            ts=parse_timestamp(current_ts),
                            host=hostname.strip(),
                            component=component.strip(),
                            message=message.strip(),
                            source=filepath,  # What benefit does this field have???
                            _target=self.target,
                        )

                    current_ts = ts_match
                    current_buf = line
                elif current_buf:
                    current_buf += line

            # For the last line
            if current_ts and current_buf:
                asdf = current_buf[len(current_ts.group()) + 1 :]
                hostname, component, message = asdf.split(" ", 2)

                yield macOSSystemLogRecord(
                    ts=parse_timestamp(current_ts),
                    host=hostname.strip(),
                    component=component.strip(),
                    message=message.strip(),
                    source=filepath,  # What benefit does this field have???
                    _target=self.target,
                )

            logfile.close()


def parse_timestamp(timestamp: re.Match, tzinfo: tzinfo = timezone.utc) -> datetime:
    return datetime.strptime(timestamp.group(), "%b %d %H:%M:%S").replace(tzinfo=tzinfo)
