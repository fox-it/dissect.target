from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

SoftwareUpdatePreferencesRecord = TargetRecordDescriptor(
    "macos/software_update_preferences",
    [
        ("varint", "last_result_code"),
        ("string", "last_attempt_system_version"),
        ("string", "last_attempt_build_version"),
        ("boolean", "automatic_download"),
        ("boolean", "automatically_install_macos_updates"),
        ("boolean", "critical_update_install"),
        ("boolean", "config_data_install"),
        ("string[]", "recommended_updates"),
        ("boolean", "splat_enabled"),
        ("boolean", "post_logout_notification"),
        ("string", "last_recommended_major_os_bundle_id"),
        ("string[]", "primary_languages"),
        ("datetime", "last_successful_date"),
        ("datetime", "last_full_successful_date"),
        ("path", "source"),
    ],
)


class SoftwareUpdatePreferencesPlugin(Plugin):
    """macOS software update preferences plugin.

    References:
        - https://eclecticlight.co/2022/11/14/how-does-ventura-update-faster-inside-the-macos-update-process/
    """

    PATH = "/Library/Preferences/com.apple.SoftwareUpdate.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No com.apple.SoftwareUpdate.plist file found")

    @export(record=SoftwareUpdatePreferencesRecord)
    def software_update_preferences(self) -> Iterator[SoftwareUpdatePreferencesRecord]:
        """Return software update preference information.

        Yields SoftwareUpdatePreferencesRecords with the following fields:

        .. code-block:: text

            last_result_code (varint): Result code of the last update attempt.
            last_attempt_system_version (string): macOS version targeted in the last update attempt.
            last_attempt_build_version (string): Build version targeted in the last update attempt.
            automatic_download (boolean): Whether automatic download of updates is enabled.
            automatically_install_macos_updates (boolean): Whether macOS updates are installed automatically.
            critical_update_install (boolean): Whether critical updates are installed automatically.
            config_data_install (boolean): Whether configuration data updates are installed automatically.
            recommended_updates (string[]): List of recommended updates.
            splat_enabled (boolean): Whether the cryptex-based update subsystem (SPLAT) is enabled.
            post_logout_notification (boolean): Whether to notify user after logout following update.
            last_recommended_major_os_bundle_id (string): Bundle identifier of last recommended major OS upgrade.
            primary_languages (string[]): Preferred system languages.
            last_successful_date (datetime): Timestamp of last successful update.
            last_full_successful_date (datetime): Timestamp of last full successful update.
            source (path): Path to the com.apple.SoftwareUpdate.plist file.
        """
        plist = plistlib.load(self.file.open())

        yield SoftwareUpdatePreferencesRecord(
            last_result_code=plist.get("LastResultCode"),
            last_attempt_system_version=plist.get("LastAttemptSystemVersion"),
            last_attempt_build_version=plist.get("LastAttemptBuildVersion"),
            automatic_download=plist.get("AutomaticDownload"),
            automatically_install_macos_updates=plist.get("AutomaticallyInstallMacOSUpdates"),
            critical_update_install=plist.get("CriticalUpdateInstall"),
            config_data_install=plist.get("ConfigDataInstall"),
            recommended_updates=plist.get("RecommendedUpdates"),
            splat_enabled=plist.get("SplatEnabled"),
            post_logout_notification=plist.get("PostSuccessfulMinorUpdatePostLogOutNotification"),
            last_recommended_major_os_bundle_id=plist.get("LastRecommendedMajorOSBundleIdentifier"),
            primary_languages=plist.get("PrimaryLanguages"),
            last_successful_date=plist.get("LastSuccessfulDate"),
            last_full_successful_date=plist.get("LastFullSuccessfulDate"),
            source=self.file,
            _target=self.target,
        )
