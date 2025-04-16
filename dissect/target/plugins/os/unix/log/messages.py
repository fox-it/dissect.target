from __future__ import annotations

import datetime
import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.utils import year_rollover_helper
from dissect.target.plugin import Plugin, alias, export
from dissect.target.plugins.os.unix.log.helpers import (
    RE_LINE,
    RE_TS,
    is_iso_fmt,
    iso_readlines,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target

MessagesRecord = TargetRecordDescriptor(
    "linux/log/messages",
    [
        ("datetime", "ts"),
        ("string", "service"),
        ("varint", "pid"),
        ("string", "message"),
        ("path", "source"),
    ],
)

DEFAULT_TS_LOG_FORMAT = "%b %d %H:%M:%S"
RE_CLOUD_INIT_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (?P<service>.*)\[(?P<log_level>\w+)\]\: (?P<message>.*)$"
)


class MessagesPlugin(Plugin):
    """Unix messages log plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.log_files = set(self._find_log_files())

    def _find_log_files(self) -> Iterator[Path]:
        log_dirs = ["/var/log/", "/var/log/installer/"]
        file_globs = ["syslog*", "messages*", "cloud-init.log*"]
        for log_dir in log_dirs:
            for glob in file_globs:
                yield from self.target.fs.path(log_dir).glob(glob)

    def check_compatible(self) -> None:
        if not self.log_files:
            raise UnsupportedPluginError("No log files found")

    @alias("syslog")
    @export(record=MessagesRecord)
    def messages(self) -> Iterator[MessagesRecord]:
        """Return contents of /var/log/messages*, /var/log/syslog* and cloud-init logs.

        Due to year rollover detection, the log contents could be returned in reversed or mixed chronological order.

        The messages log file holds information about a variety of events such as the system error messages, system
        startups and shutdowns, change in the network configuration, etc. Aims to store valuable, non-debug and
        non-critical messages. This log should be considered the "general system activity" log.

        References:
            - https://geek-university.com/linux/var-log-messages-file/
            - https://www.geeksforgeeks.org/file-timestamps-mtime-ctime-and-atime-in-linux/
            - https://cloudinit.readthedocs.io/en/latest/development/logging.html#logging-command-output
        """
        target_tz = self.target.datetime.tzinfo

        for log_file in self.log_files:
            if "cloud-init" in log_file.name:
                yield from self._parse_cloud_init_log(log_file, target_tz)
                continue

            if is_iso_fmt(log_file):
                iterable = iso_readlines(log_file)

            else:
                iterable = year_rollover_helper(log_file, RE_TS, DEFAULT_TS_LOG_FORMAT, target_tz)

            for ts, line in iterable:
                match = RE_LINE.search(line)

                if not match:
                    self.target.log.warning("Unable to parse message line in %s: %r", log_file, line)
                    continue

                yield MessagesRecord(
                    ts=ts,
                    **match.groupdict(),
                    source=log_file,
                    _target=self.target,
                )

    def _parse_cloud_init_log(
        self, log_file: Path, tzinfo: datetime.tzinfo | None = datetime.timezone.utc
    ) -> Iterator[MessagesRecord]:
        """Parse a cloud-init.log file.

        Lines are structured in the following format:
        ``YYYY-MM-DD HH:MM:SS,000 - dhcp.py[DEBUG]: Received dhcp lease on IFACE for IP/MASK``

        NOTE: ``cloud-init-output.log`` files are not supported as they do not contain structured logs.

        Args:
            ``log_file``: path to cloud-init.log file.

        Returns: ``MessagesRecord``
        """

        ts_fmt = "%Y-%m-%d %H:%M:%S,%f"

        with open_decompress(log_file, "rt") as fh:
            for line in fh:
                if not (line := line.strip()):
                    continue

                if not (match := RE_CLOUD_INIT_LINE.match(line)):
                    self.target.log.warning("Could not match cloud-init log line in file: %s", log_file)
                    self.target.log.debug("No match for line '%s'", line)
                    continue

                values = match.groupdict()

                # Actual format is ``YYYY-MM-DD HH:MM:SS,000`` (asctime with milliseconds) but python has no strptime
                # operator for 3 digit milliseconds, so we convert and pad to six digit microseconds.
                # https://github.com/canonical/cloud-init/blob/main/cloudinit/log/loggers.py#DEFAULT_LOG_FORMAT
                # https://docs.python.org/3/library/logging.html#asctime
                raw_ts, _, milliseconds = values["ts"].rpartition(",")
                raw_ts += "," + str(int(milliseconds) * 1000).zfill(6)

                try:
                    ts = datetime.datetime.strptime(raw_ts, ts_fmt).replace(tzinfo=tzinfo)

                except ValueError as e:
                    self.target.log.warning("Timestamp '%s' does not match format '%s'", raw_ts, ts_fmt)
                    self.target.log.debug("", exc_info=e)
                    ts = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, tzinfo=datetime.timezone.utc)

                yield MessagesRecord(
                    ts=ts,
                    service=values["service"],
                    pid=None,
                    message=values["message"],
                    source=log_file,
                    _target=self.target,
                )
