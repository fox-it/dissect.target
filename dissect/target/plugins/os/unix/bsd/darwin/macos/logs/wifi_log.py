from __future__ import annotations

import re
from datetime import timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

RE_TS = re.compile(
    r"""
    ^
    (?P<ts>
        [A-Za-z]{3}
        \s+
        [A-Za-z]{3}
        \s+
        \d{1,2}
        \s+
        \d{2}:\d{2}:\d{2}
        \.\d{3}
    )
    """,
    re.VERBOSE,
)


WifiLogRecord = TargetRecordDescriptor(
    "wifi_log",
    [
        ("datetime", "ts"),
        ("string", "host"),
        ("string", "message"),
        ("path", "source"),
    ],
)


class WifiLogPlugin(Plugin):
    """Plugin to parse WiFi logs on macOS.

    Contains information on WiFi connections and known hotspots

    References:
        - https://www.cyberengage.org/post/macos-incident-response-tactics-log-analysis-and-forensic-tools
        - https://www.hackthelogs.com/MacLogs.html
    """

    PATH = "/var/log/wifi.log"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No wifi.log file found")

    @export(record=WifiLogRecord)
    def wifi_log(self) -> Iterator[WifiLogRecord]:
        """Return all macOS Wi-Fi log messages.

        Yields WifiLogRecord with the following fields:

        .. code-block:: text

            ts (datetime): Timestamp (UTC) derived from the log line.
            host (string): Hostname parsed from the log entry.
            message (string): Log message content.
            source (path): Path to the wifi.log file.
        """
        current_buf = ""

        for ts, line in year_rollover_helper(
            self.file,
            RE_TS,
            "%a %b %d %H:%M:%S.%f",
            timezone.utc,
        ):
            current_buf = line + "\n\t" + current_buf
            if ts:
                match = RE_TS.match(current_buf)
                asdf = current_buf[match.end() :].lstrip(" ")
                hostname, message = asdf.split(" ", 1)

                yield WifiLogRecord(
                    ts=ts,
                    host=hostname.strip(),
                    message=message.strip(),
                    source=self.file,
                    _target=self.target,
                )

                current_buf = ""
