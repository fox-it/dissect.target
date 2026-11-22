from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


FsckAPFSLogRecord = TargetRecordDescriptor(
    "macos/fsck_apfs_log",
    [
        ("datetime", "ts"),
        ("string", "disk_path"),
        ("string", "message"),
        ("path", "source"),
    ],
)


RE_TIMESTAMP_PATTERN = re.compile(
    r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}$"
)


class FsckAPFSLogPlugin(Plugin):
    """Plugin to parse File System Consistency Check (FSCK) logs on macOS.

    The fsck_apfs.log file is a macOS log file associated with
    filesystem checking activity. The fsck utility is used to check and
    optionally repair filesystems.

    References:
        - https://linux.die.net/man/8/fsck
        - https://www.cyberengage.org/post/macos-incident-response-tactics-log-analysis-and-forensic-tools
        - https://www.hackthelogs.com/MacLogs.html
    """

    FSCK_APFS_LOG_PATH = "/var/log/fsck_apfs.log"

    def check_compatible(self) -> None:
        if not self.target.fs.exists(self.FSCK_APFS_LOG_PATH):
            raise UnsupportedPluginError("No fsck_apfs.log file found.")

    @export(record=FsckAPFSLogRecord)
    def fsck_apfs_log(self) -> Iterator[FsckAPFSLogRecord]:
        """Return all macOS fsck_apfs log messages.

        Yields FsckAPFSLogRecord with the following fields:

        .. code-block:: text

            ts (datetime): Timestamp (UTC), if present in the log line.
            disk_path (string): Disk or APFS volume identifier from the log line.
            message (string): Log message content.
            source (path): Path to the fsck_apfs.log file.

        Lines without a recognizable timestamp will have ts set to None.
        """
        with self.target.fs.path(self.FSCK_APFS_LOG_PATH).open(mode="rt") as fh:
            for line in fh:
                if line != "\n":
                    parts = line.split(" ", 1)

                    disk_path, message = parts
                    disk_path = disk_path.strip(":")
                    ts = None

                    if ts_match := RE_TIMESTAMP_PATTERN.search(message):
                        ts = datetime.strptime(ts_match.group(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)

                    yield FsckAPFSLogRecord(
                        ts=ts,
                        disk_path=disk_path.strip(),
                        message=message.strip(),
                        source=self.FSCK_APFS_LOG_PATH,
                        _target=self.target,
                    )
