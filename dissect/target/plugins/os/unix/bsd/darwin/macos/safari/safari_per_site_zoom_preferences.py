from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

SafariPerSiteZoomPreferencesRecord = TargetRecordDescriptor(
    "macos/safari_per_site_zoom_preferences",
    [
        ("string", "map_of_hostnames_to_zoom_preferences"),
        ("string", "map_of_ck_record_names_to_ck_records"),
        ("varint", "zoom_preference_version"),
        ("path", "source"),
    ],
)


class SafariPerSiteZoomPreferencesPlugin(Plugin):
    """macOS Safari per site zoom preferences (plist) plugin.

    References:
        - https://www.magnetforensics.com/blog/macos-safari-preferences-and-privacy/
    """

    USER_PATH = ("Library/Safari/PerSiteZoomPreferences.plist",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No PerSiteZoomPreferences.plist files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=SafariPerSiteZoomPreferencesRecord)
    def safari_per_site_zoom_preferences(self) -> Iterator[SafariPerSiteZoomPreferencesRecord]:
        """Return macOS Safari per site zoom preferences.

        Yields SafariPerSiteZoomPreferencesRecords with the following fields:

        .. code-block:: text

            map_of_hostnames_to_zoom_preferences (string): map of hostnames to zoom preferences.
            map_of_ck_record_names_to_ck_records (string): map of ck record names to ck records.
            zoom_preference_version (varint): Zoom preference version.
            source (path): Path to the PerSiteZoomPreferences.plist file.
        """
        for file in self.files:
            plist = plistlib.load(file.open())

            yield SafariPerSiteZoomPreferencesRecord(
                map_of_hostnames_to_zoom_preferences=plist.get("MapOfHostnamesToZoomPreferences"),
                map_of_ck_record_names_to_ck_records=plist.get("MapOfCKRecordNamesToCKRecords"),
                zoom_preference_version=plist.get("ZoomPreferenceVersion"),
                source=file,
                _target=self.target,
            )


# MapOfHostnamesToZoomPreferences and MapOfCKRecordNamesToCKRecords fields are empty in current test data
# TODO: Get test file with actual data
