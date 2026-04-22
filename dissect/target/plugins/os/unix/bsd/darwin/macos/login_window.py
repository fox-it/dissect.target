from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.plist import build_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")


class LoginWindowPlugin(Plugin):
    """macOS login window plugin."""

    SYSTEM_LOGIN_WINDOW_PATHS = (
        "/Library/Preferences/com.apple.loginwindow.plist",
        "/var/root/Library/Preferences/com.apple.loginwindow.plist",
        "/private/var/root/Library/Preferences/com.apple.loginwindow.plist",
    )

    USER_LOGIN_WINDOW_PATHS = (
        "Library/Preferences/loginwindow.plist",
        "Library/Preferences/ByHost/com.apple.loginwindow.plist",
        "Library/Preferences/ByHost/com.apple.loginwindow.*.plist",
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.login_window_files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.login_window_files):
            raise UnsupportedPluginError("No Login Window files found")

    def _find_files(self) -> None:
        # --- System-wide ---
        for pattern in self.SYSTEM_LOGIN_WINDOW_PATHS:
            for path in self.target.fs.glob(pattern):
                self.login_window_files.add(path)

        # --- Per-user ---
        for _, path in _build_userdirs(self, self.USER_LOGIN_WINDOW_PATHS):
            self.login_window_files.add(path)

    @export(record=DynamicDescriptor(["string"]))
    # @export(output="yield")
    def login_window(self) -> Iterator[DynamicDescriptor]:
        """Yield macOS login window plist files."""
        yield from build_records(self, "macos/login_window", self.login_window_files)
