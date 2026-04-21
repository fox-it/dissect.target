from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

InstallationHistoryRecord = TargetRecordDescriptor(
    "macos/installation_history",
    [
        ("datetime", "date"),
        ("string", "display_name"),
        ("string", "display_version"),
        ("string", "process_name"),
        ("path", "source"),
    ],
)


class InstallationHistoryPlugin(Plugin):
    """macOS Software installation history property list plugin."""

    PATH = "/Library/Receipts/InstallHistory.plist"

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
            raise UnsupportedPluginError("No InstallHistory.plis file found")

    @export(record=InstallationHistoryRecord)
    def installation_history(self) -> Iterator[InstallationHistoryRecord]:
        """Yield installation history information."""
        plist = plistlib.load(self.file.open())
        data = plist[0]

        display_name = data.get("displayName")
        display_version = data.get("displayVersion")
        process_name = data.get("processName")
        date = data.get("date")

        yield InstallationHistoryRecord(
            date=date,
            display_name=display_name,
            display_version=display_version,
            process_name=process_name,
            source=self.file,
            _target=self.target,
        )
