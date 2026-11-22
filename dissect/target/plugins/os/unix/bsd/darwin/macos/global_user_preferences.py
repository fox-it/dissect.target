from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


class GlobalUserPreferencesPlugin(Plugin):
    """macOS global user preferences plugin.

    .GlobalPreferences.plist files are located in each user's
    ~/Library/Preferences directory. This property list contains
    system-wide preference settings that apply across applications for the user.
    """

    PATHS = ("Library/Preferences/.GlobalPreferences.plist",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No global user preferences files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.PATHS):
            files.add(path)
        return files

    @export(record=DynamicDescriptor(["string"]))
    def global_user_preferences(self) -> Iterator[DynamicDescriptor]:
        """Yield global user preference information."""
        yield from build_plist_records(self, self.files, function_name="macos/global_user_preferences")
