from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

LoginWindowRecord = TargetRecordDescriptor(
    "macos/login_window",
    [
        ("string", "build_version_as_string"),
        ("varint", "build_version_stamp_as_number"),
        ("string", "system_version_stamp_as_string"),
        ("varint", "system_version_stamp_as_number"),
        ("path", "source"),
    ],
)

# Found these fields on macOS Tahoe, but not on Ventura
MiniBuddyRecord = TargetRecordDescriptor(
    "macos/login_window/mini_buddy",
    [
        ("boolean", "mini_buddy_launch"),
        ("path", "source"),
    ],
)

# Found these fields on macOS Ventura, but not on Tahoe
BundleRecord = TargetRecordDescriptor(
    "macos/login_window/bundle",
    [
        ("boolean", "hide"),
        ("string", "bundle_id"),
        ("path", "path"),
        ("varint", "background_state"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

LoginWindowRecordRecords = (LoginWindowRecord, MiniBuddyRecord, BundleRecord)

FIELD_MAPPINGS = {
    "BuildVersionStampAsString": "build_version_as_string",
    "SystemVersionStampAsNumber": "system_version_stamp_as_number",
    "SystemVersionStampAsString": "system_version_stamp_as_string",
    "BuildVersionStampAsNumber": "build_version_stamp_as_number",
    "MiniBuddyLaunch": "mini_buddy_launch",
    "Hide": "hide",
    "BundleID": "bundle_id",
    "Path": "path",
    "BackgroundState": "background_state",
}


class LoginWindowPlugin(Plugin):
    """macOS login window plugin.

    Parses configuration settings related to macOS login window behavior.
    Login window is the system component that handles actions during login and logout,
    such as relaunching applications on login.

    References:
        - https://developer.apple.com/documentation/devicemanagement/loginwindowscripts
        - https://cocomelonc.github.io/macos/2026/03/29/mac-malware-persistence-7.html
        - https://forums.macrumors.com/threads/keychain-minibuddyitem-what-this-is.2077558/
    """

    SYSTEM_LOGIN_WINDOW_PATHS = (
        "/Library/Preferences/com.apple.loginwindow.plist",
        "/var/root/Library/Preferences/com.apple.loginwindow.plist",
    )

    USER_LOGIN_WINDOW_PATHS = (
        "Library/Preferences/loginwindow.plist",
        "Library/Preferences/ByHost/com.apple.loginwindow.plist",
        "Library/Preferences/ByHost/com.apple.loginwindow.*.plist",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.login_window_files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.login_window_files):
            raise UnsupportedPluginError("No Login Window files found")

    def _find_files(self) -> set:
        login_window_files = set()
        for pattern in self.SYSTEM_LOGIN_WINDOW_PATHS:
            for path in self.target.fs.glob(pattern):
                login_window_files.add(path)
        for _, path in _build_userdirs(self, self.USER_LOGIN_WINDOW_PATHS):
            login_window_files.add(path)
        return login_window_files

    @export(record=LoginWindowRecordRecords)
    def login_window(self) -> Iterator[LoginWindowRecordRecords]:
        """Return macOS login window configuration settings.

        Yields the following record types extracted from the
        com.apple.loginwindow.plist files:

        .. code-block:: text

            LoginWindowRecord:
                build_version_as_string (string): OS build version.
                build_version_stamp_as_number (varint): Numeric build stamp.
                system_version_stamp_as_string (string): OS version string.
                system_version_stamp_as_number (varint): Numeric system version.
                source (path): Path to the plist file.

            MiniBuddyRecord:
                mini_buddy_launch (boolean): Whether MiniBuddy, the macOS Setup Assistant, should launch on login.
                source (path): Path to the plist file.

            BundleRecord:
                hide (boolean): Whether the app is hidden on relaunch.
                bundle_id (string): Application bundle identifier.
                path (path): Path to the application bundle.
                background_state (varint): Relaunch background state, 2 = background process.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the plist file.
        """
        yield from build_plist_records(
            self, self.login_window_files, LoginWindowRecordRecords, field_mappings=FIELD_MAPPINGS
        )
