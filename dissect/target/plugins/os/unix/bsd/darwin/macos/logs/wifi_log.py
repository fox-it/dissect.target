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
    [("datetime", "ts"), ("string", "host"), ("string", "message"), ("path", "source")],
)


class WifiLogPlugin(Plugin):
    """macOS WiFi logs plugin."""

    PATH = "/var/log/wifi.log"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = None
        self._resolve_file()

    def _resolve_file(self) -> None:
        path = self.target.fs.path(self.PATH)
        if path.exists():
            self.file = path

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No wifi.log file found")

    @export(record=WifiLogRecord)
    def wifi_log(self) -> Iterator[WifiLogRecord]:
        """Return all macOS WiFi log messages."""
        timestamps = [ts for ts, _ in year_rollover_helper(self.file, RE_TS, "%a %b %d %H:%M:%S.%f", timezone.utc)]
        timestamps.reverse()
        ts_iter = iter(timestamps)

        with self.file.open(mode="rt") as logfile:
            current_ts_match: re.Match[str] | None = None
            current_buf = ""

            for line in logfile.readlines():
                if ts_match := RE_TS.match(line):
                    if current_ts_match:
                        asdf = current_buf[len(current_ts_match.group()) + 1 :]
                        hostname, message = asdf.split(" ", 1)

                        yield WifiLogRecord(
                            ts=next(ts_iter, None),
                            host=hostname.strip(),
                            message=message.strip(),
                            source=self.file,
                            _target=self.target,
                        )

                    current_ts_match = ts_match
                    current_buf = line

                elif current_buf:
                    current_buf += line

            if current_ts_match and current_buf:
                asdf = current_buf[len(current_ts_match.group()) + 1 :]
                hostname, message = asdf.split(" ", 1)

                yield WifiLogRecord(
                    ts=next(ts_iter, None),
                    host=hostname.strip(),
                    message=message.strip(),
                    source=self.file,
                    _target=self.target,
                )
