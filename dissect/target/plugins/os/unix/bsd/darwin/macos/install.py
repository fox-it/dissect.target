from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

# Do we call it macos or osx?
OSXInstallLogRecord = TargetRecordDescriptor(
    "osx/install",
    [
        ("datetime", "ts"),
        ("string", "host"),
        ("string", "component"),
        ("string", "message"),
    ],
)

RE_TIMESTAMP_PATTERN = re.compile(
    r"^(?:"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|"
    r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[+-]\d{1,2}(?::?\d{2})?"
    r")"
)


class InstallLog(Plugin):
    """Return information related software installations and updates on OS X.

    References:
        - https://sansorg.egnyte.com/dl/m9ftGF7heI
    """

    INSTALL_LOG_PATH = "/var/log/install.log"

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self) -> None:
        if not self.target.fs.exists(self.INSTALL_LOG_PATH):
            raise UnsupportedPluginError("No install.log file found.")

    @export(record=OSXInstallLogRecord)
    def installlog(self) -> Iterator[OSXInstallLogRecord]:
        """Return all OS X install log messages.

        Yields OSXInstallLogRecord instances with fields:

        .. code-block:: text

            ts (datetime): Timestamp of the log line.
            host (str): Hostname.
            component (str): Component name.
            message (str): Log message.

        References:
            - https://sansorg.egnyte.com/dl/m9ftGF7heI
        """

        logfile = self.target.fs.path(self.INSTALL_LOG_PATH).open(mode="rt")

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

                    yield OSXInstallLogRecord(
                        ts=parse_timestamp(current_ts),
                        host=hostname.strip(),
                        component=component.strip(),
                        message=message.strip(),
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

            yield OSXInstallLogRecord(
                ts=parse_timestamp(current_ts),
                host=hostname.strip(),
                component=component.strip(),
                message=message.strip(),
                _target=self.target,
            )


def parse_timestamp(timestamp: re.Match) -> datetime:
    # I could not find docs about this but it seems to be the case that when you
    # start installing your macbook, it outputs the timestamp in this BSD style
    # format without any timezone info. After some messages it starts outputting
    # ISO timestamps with timezone info. From those timestamps I kind of inferred
    # that this is actually just UTC.
    ts = None
    try:
        ts = datetime.fromisoformat(timestamp.group())
    except ValueError:
        ts = datetime.strptime(timestamp.group(), "%b %d %H:%M:%S").replace(tzinfo=timezone.utc)

    return ts
