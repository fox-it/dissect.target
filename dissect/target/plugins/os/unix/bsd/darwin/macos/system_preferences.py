from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.plist import build_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")


class SystemPreferencesPlugin(Plugin):
    """macOS system preferences plugin."""

    PATHS = ("/Library/Preferences/**/*.plist",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = set()
        self._find_files()

    def _find_files(self) -> None:
        for pattern in self.PATHS:
            for path in self.target.fs.glob(pattern):
                self.files.add(path)

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No system preferences files found")

    @export(record=DynamicDescriptor(["string"]))
    def system_preferences(self) -> Iterator[DynamicDescriptor]:
        """Yield system preference information."""
        yield from build_records(self, "macos/system_preferences", self.files)
