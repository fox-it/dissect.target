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

FsckAPFSLogRecord = TargetRecordDescriptor(
    "macos/fsck_apfs_log",
    [
        ("string", "disk_path"),
        ("string", "message"),
        ("datetime", "ts"),
        ("path", "source"),
    ],
)


RE_TIMESTAMP_PATTERN = re.compile(
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}$"
)


class FsckAPFSLogPlugin(Plugin):
    """Return information related to fsck_apfs log entries on macOS."""

    FSCK_APFS_LOG_PATH = "/var/log/fsck_apfs.log"

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self) -> None:
        if not self.target.fs.exists(self.FSCK_APFS_LOG_PATH):
            raise UnsupportedPluginError("No fsck_apfs.log file found.")

    @export(record=FsckAPFSLogRecord)
    def fsck_apfs_log(self) -> Iterator[FsckAPFSLogRecord]:
        """Return all fsck_apfs log messages."""
        logfile = self.target.fs.path(self.FSCK_APFS_LOG_PATH).open(mode="rt")

        for line in logfile.readlines():
            if line != "\n":
                parts = line.split(" ", 1)

                disk_path, message = parts
                disk_path = disk_path.strip(":")
                ts = None

                if ts_match := RE_TIMESTAMP_PATTERN.search(message):
                    ts = datetime.strptime(ts_match.group(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)

                yield FsckAPFSLogRecord(
                    disk_path=disk_path.strip(),
                    message=message.strip(),
                    ts=ts,
                    source=self.FSCK_APFS_LOG_PATH,
                    _target=self.target,
                )
