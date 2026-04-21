from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.plist import build_records
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.userdirs import _build_userdirs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")

LoginItemsRecord = TargetRecordDescriptor(
    "macos/login_items",
    [
        ("varint", "generation"),
        ("varint", "backgroundAppRefreshLoadCount"),
        ("boolean", "launchServicesItemsImported"),
        ("boolean", "serviceManagementLoginItemsMigrated"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

LoginItemsRecords = (LoginItemsRecord,)


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

    @export(record=DynamicDescriptor(["string"]))
    # @export(output="yield")
    def login_items(self) -> Iterator[DynamicDescriptor]:
        """Yield macOS login items plist files."""
        yield from build_records(self, "macos/login_items", self.login_items_files, LoginItemsRecords)
