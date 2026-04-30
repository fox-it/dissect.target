from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import _build_userdirs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")

LoginItemsRecord = TargetRecordDescriptor(
    "macos/login_items",
    [
        ("varint", "generation"),
        ("varint", "background_app_refresh_load_count"),
        ("boolean", "launch_services_items_imported"),
        ("boolean", "service_management_login_items_migrated"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

LoginItemsRecords = (LoginItemsRecord,)

FIELD_MAPPINGS = {
    "backgroundAppRefreshLoadCount": "background_app_refresh_load_count",
    "launchServicesItemsImported": "launch_services_items_imported",
    "serviceManagementLoginItemsMigrated": "service_management_login_items_migrated",
}


class LoginItemsPlugin(Plugin):
    """macOS login items plugin."""

    SYSTEM_LOGIN_ITEMS_PATHS = ("/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm",)

    USER_LOGIN_ITEMS_PATHS = (
        "Library/Preferences/com.apple.loginitems.plist",
        "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.login_items_files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.login_items_files):
            raise UnsupportedPluginError("No Login Items files found")

    def _find_files(self) -> None:
        # --- System-wide ---
        for pattern in self.SYSTEM_LOGIN_ITEMS_PATHS:
            for path in self.target.fs.glob(pattern):
                self.login_items_files.add(path)

        # --- Per-user ---
        for _, path in _build_userdirs(self, self.USER_LOGIN_ITEMS_PATHS):
            self.login_items_files.add(path)

    @export(record=LoginItemsRecord)
    # @export(output="yield")
    def login_items(self) -> Iterator[LoginItemsRecord]:
        """Yield macOS login items plist files."""
        yield from build_plist_records(self, self.login_items_files, LoginItemsRecords, field_mappings=FIELD_MAPPINGS)
