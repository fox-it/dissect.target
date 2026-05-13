from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import parse_timestamp

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

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
    """Return information related software installations and updates on macOS.

    References:
        - https://sansorg.egnyte.com/dl/m9ftGF7heI
    """

    INSTALL_LOG_PATH = "/var/log/install.log"

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self) -> None:
        if not self.target.fs.exists(self.INSTALL_LOG_PATH):
            raise UnsupportedPluginError("No install.log file found.")

    @export(record=InstallLogRecord)
    def install_log(self) -> Iterator[InstallLogRecord]:
        """Return all macOS install log messages.

        Yields InstallLogRecord instances with fields:

        .. code-block:: text

            ts (datetime): Timestamp of the log line.
            host (str): Hostname.
            component (str): Component name.
            message (str): Log message.
            source (path): Path to the log file.

        References:
            - https://sansorg.egnyte.com/dl/m9ftGF7heI
        """
        logfile = self.target.fs.path(self.INSTALL_LOG_PATH).open(mode="rt")

        current_ts: re.Match[str] | None = None
        current_buf = ""

        for line in logfile.readlines():
            if ts_match := RE_TIMESTAMP_PATTERN.match(line):
                if current_ts:
                    asdf = current_buf[len(current_ts.group()) + 1 :]

                    parts = asdf.split(" ", 2)

                    if len(parts) == 3:
                        hostname, component, message = parts
                    elif len(parts) == 2:
                        hostname, message = parts
                        component = None
                    yield InstallLogRecord(
                        ts=parse_timestamp(current_ts),
                        host=hostname.strip(),
                        component=component.strip() if component else None,
                        message=message.strip(),
                        source=self.INSTALL_LOG_PATH,
                        _target=self.target,
                    )

                current_ts = ts_match
                current_buf = line
            elif current_buf:
                current_buf += line

        if current_ts and current_buf:
            asdf = current_buf[len(current_ts.group()) + 1 :]
            hostname, component, message = asdf.split(" ", 2)

            yield InstallLogRecord(
                ts=parse_timestamp(current_ts),
                host=hostname.strip(),
                component=component.strip(),
                message=message.strip(),
                source=self.INSTALL_LOG_PATH,
                _target=self.target,
            )
