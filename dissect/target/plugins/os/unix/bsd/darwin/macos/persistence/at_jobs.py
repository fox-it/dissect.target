from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")

AtJobsRecord = TargetRecordDescriptor(
    "macos/at_jobs",
    [
        ("string", "queue"),
        ("varint", "seq"),
        ("datetime", "execution_time"),
        ("path", "source"),
    ],
)

FIELD_MAPPINGS = {
    "backgroundAppRefreshLoadCount": "background_app_refresh_load_count",
    "launchServicesItemsImported": "launch_services_items_imported",
    "serviceManagementLoginItemsMigrated": "service_management_login_items_migrated",
}


class AtJobsPlugin(Plugin):
    """macOS at jobs plugin."""

    PATHS = ("/usr/lib/cron/jobs/*",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.at_jobs_files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.at_jobs_files):
            raise UnsupportedPluginError("No At Jobs files found")

    def _find_files(self) -> None:
        for pattern in self.PATHS:
            for path in self.target.fs.glob(pattern):
                self.at_jobs_files.add(path)

    @export(record=AtJobsRecord)
    def at_jobs(self) -> Iterator[AtJobsRecord]:
        """Yield macOS at jobs."""
        for file in self.at_jobs_files:
            name = Path(file).name

            if name in (".SEQ", ".lockfile"):
                continue

            if len(name) < 6:
                continue

            queue = name[0]
            seq = int(name[1:6])
            time_hex = name[6:]

            execution_time = None
            try:
                minutes = int(time_hex, 16)
                execution_time = minutes * 60
            except ValueError:
                pass

            yield AtJobsRecord(
                queue=queue,
                seq=seq,
                execution_time=execution_time,
                source=file,
            )
