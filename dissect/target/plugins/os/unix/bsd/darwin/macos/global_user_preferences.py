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


class GlobalUserPreferencesPlugin(Plugin):
    """macOS global user preferences plugin."""

    PATHS = ("Library/Preferences/.GlobalPreferences.plist",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No global user preferences files found")

    def _find_files(self) -> None:
        for _, path in _build_userdirs(self, self.PATHS):
            self.files.add(path)

    @export(record=DynamicDescriptor(["string"]))
    def global_user_preferences(self) -> Iterator[DynamicDescriptor]:
        """Yield global user preference information."""
        yield from build_records(self, "macos/global_user_preferences", self.files)
