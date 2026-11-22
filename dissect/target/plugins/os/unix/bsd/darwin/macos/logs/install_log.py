from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.parse_timestamp import parse_timestamp

if TYPE_CHECKING:
    from collections.abc import Iterator


InstallLogRecord = TargetRecordDescriptor(
    "macos/install_log",
    [
        ("datetime", "ts"),
        ("string", "host"),
        ("string", "component"),
        ("string", "message"),
        ("path", "source"),
    ],
)

RE_TIMESTAMP_PATTERN = re.compile(
    r"^(?:"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|"
    r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[+-]\d{1,2}(?::?\d{2})?"
    r")"
)


class InstallLogPlugin(Plugin):
    """Plugin to parse install logs on macOS.

    Contains information on the software installation history.

    References:
        - https://sansorg.egnyte.com/dl/m9ftGF7heI
        - https://www.cyberengage.org/post/macos-incident-response-tactics-log-analysis-and-forensic-tools
        - https://www.hackthelogs.com/MacLogs.html
    """

    INSTALL_LOG_PATH = "/var/log/install.log"

    def check_compatible(self) -> None:
        if not self.target.fs.exists(self.INSTALL_LOG_PATH):
            raise UnsupportedPluginError("No install.log file found.")

    def parse_log(self, current_ts: re.Match[str], current_buf: str) -> Iterator[InstallLogRecord]:
        # Log format: "<timestamp> <hostname> <component>: <message>"
        # Strip the timestamp (and following space) to extract the rest of the line
        asdf = current_buf[len(current_ts.group()) + 1 :]

        # Split into hostname, component and message
        parts = asdf.split(" ", 2)

        if len(parts) == 3:
            hostname, component, message = parts
            yield InstallLogRecord(
                ts=parse_timestamp(current_ts),
                host=hostname.strip(),
                component=component.strip() if component else None,
                message=message.strip(),
                source=self.INSTALL_LOG_PATH,
                _target=self.target,
            )
        elif len(parts) != 3:
            self.target.log.warning(
                "Skipping malformed install log entry in %s: "
                "expected 3 fields (hostname, component, message), got %d -> '%s'",
                self.INSTALL_LOG_PATH,
                len(parts),
                asdf.strip(),
            )

    @export(record=InstallLogRecord)
    def install_log(self) -> Iterator[InstallLogRecord]:
        """Return all macOS install log messages.

        Yields InstallLogRecord with the following fields:

        .. code-block:: text

            ts (datetime): Timestamp (UTC).
            host (string): Hostname parsed from the log line.
            component (string): Component responsible for the log entry.
            message (string): Log message content.
            source (path): Path to the install.log file.
        """
        current_ts: re.Match[str] | None = None
        current_buf = ""
        with self.target.fs.path(self.INSTALL_LOG_PATH).open(mode="rt") as fh:
            for line in fh:
                # New timestamp indicates the start of new log entry.
                if ts_match := RE_TIMESTAMP_PATTERN.match(line):
                    # If previous log entry exists, parse it.
                    if current_ts:
                        yield from self.parse_log(current_ts, current_buf)

                    current_ts = ts_match
                    current_buf = line

                # Lines without a timestamp are part of the previous log entry.
                elif current_buf:
                    current_buf += line  # append continuation

            # If previous log entry exists, parse it.
            if current_ts and current_buf:
                yield from self.parse_log(current_ts, current_buf)
