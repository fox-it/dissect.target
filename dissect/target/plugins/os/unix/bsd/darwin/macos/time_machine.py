from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

TimeMachineRecord = TargetRecordDescriptor(
    "macos/time_machine",
    [
        ("varint", "preferences_version"),
        ("path", "source"),
    ],
)


class TimeMachinePlugin(Plugin):
    """macOS time machine plugin."""

    PATH = "/Library/Preferences/com.apple.TimeMachine.plist"

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
            raise UnsupportedPluginError("No com.apple.TimeMachine.plist file found")

    @export(record=TimeMachineRecord)
    def time_machine(self) -> Iterator[TimeMachineRecord]:
        """Yield time machine information."""
        plist = plistlib.load(self.file.open())

        yield TimeMachineRecord(
            preferences_version=plist.get("PreferencesVersion"),
            source=self.file,
            _target=self.target,
        )
