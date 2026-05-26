@ -1,59 +1,55 @@
from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

AirportPreferencesRecord = TargetRecordDescriptor(
    "macos/airport_preferences",
    [
        ("varint", "counter"),
        ("string", "device_uuid"),
        ("string", "version"),
        ("string", "preferred_order"),
        ("path", "source"),
    ],
)


class AirportPreferencesPlugin(Plugin):
    """macOS AirPort (WiFi) preferences plugin."""

    PATH = "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"

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
            raise UnsupportedPluginError("No com.apple.airport.preferences.plist file found")

    @export(record=AirportPreferencesRecord)
    def airport_preferences(self) -> Iterator[AirportPreferencesRecord]:
        """Yield AirPort preference information."""
        plist = plistlib.load(self.file.open())

        yield AirportPreferencesRecord(
            counter=plist.get("Counter"),
            device_uuid=plist.get("DeviceUUID"),
            version=plist.get("Version"),
            preferred_order=plist.get("PreferredOrder"),
            source=self.file,
            _target=self.target,
        )
