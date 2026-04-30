from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\&gt;\&lt;]")


class MacOSResourcesLocalizableStringsPlugin(Plugin):
    """macOS Resources Localizable.strings plist file."""

    PATHS = (
        "/System/Library/CoreServices/*.app/Contents/Resources/*.lproj/Localizable.strings",
        "/System/Library/Extensions/*.kext/Contents/Resources/*.lproj/Localizable.strings",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/Resources/*.lproj/Localizable.strings",
        "/System/Library/Frameworks/*.framework/Versions/A/Frameworks/*.framework/Versions/A/Resources/*.lproj/Localizable.strings",
        "/System/Library/PreferencePanes/*.prefPane/Contents/Resources/*.lproj/Localizable.strings",
        "/System/Library/PrivateFrameworks/*.framework/Versions/A/Plugins/*.bundle/Contents/Resources/*.lproj/Localizable.strings",
        "/System/Library/PrivateFrameworks/*.framework/Versions/A/Resources/*.lproj/Localizable.strings",
        "/System/Library/SystemProfiler/*/Contents/Resources/*.lproj/Localizable.strings",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = set()
        self._find_files()

    def _find_files(self) -> None:
        for pattern in self.PATHS:
            for path in self.target.fs.glob(pattern):
                self.files.add(path)

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError("No Resources Localizable.strings files found")

    @export(record=DynamicDescriptor(["string"]))
    def resources_localizable_strings(self) -> Iterator[DynamicDescriptor]:
        """Yield Resources Localizable.strings information."""
        yield from build_plist_records(self, self.files, function_name="macos/resources_localizable_strings")
