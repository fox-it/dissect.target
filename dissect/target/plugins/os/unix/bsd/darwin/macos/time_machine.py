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
    """macOS Time Machine plugin.

    Parses Time Machine preferences. Time Machine is macOS's backup system.
    """

    PATH = "/Library/Preferences/com.apple.TimeMachine.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No com.apple.TimeMachine.plist file found")

    @export(record=TimeMachineRecord)
    def time_machine(self) -> Iterator[TimeMachineRecord]:
        """Return macOS Time Machine preferences.

        Yields TimeMachineRecord with the following fields:

        .. code-block:: text

            preferences_version (varint): Version of the Time Machine preferences.
            source (path): Path to the com.apple.TimeMachine.plist file.
        """
        plist = plistlib.load(self.file.open())

        yield TimeMachineRecord(
            preferences_version=plist.get("PreferencesVersion"),
            source=self.file,
            _target=self.target,
        )

# I was only able to find a preferences_version field in the plist file on a fresh Tahoe system.
# TODO: Check if more fields show up in the plist file depending on user activity.
