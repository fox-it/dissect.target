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


class ResourcesInfoStringsPlugin(Plugin):
    """macOS Resources InfoPlist.strings plist file."""

    PATHS = (
        "/Applications/*.app/Contents/Resources/*.help/Contents/Resources/*.lproj/InfoPlist.strings",
        "/Applications/*/*.app/Contents/Resources/*.help/Contents/Resources/*.lproj/InfoPlist.strings",
        "/System/Library/CoreServices/*.app/Contents/Resources/*.lproj/InfoPlist.strings",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.bundle/Contents/Resources/*.lproj/InfoPlist.strings",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/Resources/*.bundle/Contents/Resources/*.lproj/InfoPlist.strings",
        "/System/Library/Extensions/*.kext/Contents/Resources/InfoPlist.strings",
        "/System/Library/Extensions/*.kext/Contents/Resources/*.lproj/InfoPlist.strings",
        "/System/Library/Filesystems/*/*.kext/Contents/Resources/*.lproj/InfoPlist.strings",
        "/System/Library/Filesystems/*/Encodings/*.kext/Contents/Resources/*.lproj/InfoPlist.strings",
        "/System/Library/PrivateFrameworks/*.framework/Versions/A/Resources/*.kext/Contents/Resources/*.lproj/InfoPlist.strings",
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
            raise UnsupportedPluginError("No Resources InfoPlist.strings files found")

    @export(record=DynamicDescriptor(["string"]))
    def resources_info_strings(self) -> Iterator[DynamicDescriptor]:
        """Yield Resources InfoPlist.strings information."""
        yield from build_plist_records(self, self.files, function_name="macos/resources_info_strings")
