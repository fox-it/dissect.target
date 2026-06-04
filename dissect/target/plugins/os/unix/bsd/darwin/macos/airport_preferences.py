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
        ("string[]", "preferred_order"),
        ("varint", "version_number"),
        ("path", "source"),
    ],
)


class AirportPreferencesPlugin(Plugin):
    """macOS AirPort (WiFi) preferences plugin.

    Contains WiFi network information.

    References:
        - https://apple.stackexchange.com/questions/301346/how-can-i-better-sort-and-set-wifi-network-preferences-on-mac
    """

    PATH = "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No com.apple.airport.preferences.plist file found")

    @export(record=AirportPreferencesRecord)
    def airport_preferences(self) -> Iterator[AirportPreferencesRecord]:
        """Return macOS AirPort (Wi-Fi) preferences.

        Yields AirportPreferencesRecord with the following fields:

        .. code-block:: text

            counter (varint): The Counter key of the plist.
            device_uuid (string): UUID of the device.
            preferred_order (string[]): Ordered list of known Wi-Fi network SSIDs.
            version_number (varint): The version number of the plist.
            source (path): Path to the com.apple.airport.preferences.plist file.
        """
        plist = plistlib.load(self.file.open())

        yield AirportPreferencesRecord(
            counter=plist.get("Counter"),
            device_uuid=plist.get("DeviceUUID"),
            preferred_order=plist.get("PreferredOrder"),
            version_number=plist.get("Version"),
            source=self.file,
            _target=self.target,
        )
