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


class ContentsInfoPlugin(Plugin):
    """macOS contents info plugin."""

    PATHS = (
        "/Applications/*/*.app/Contents/Info.plist",
        "/Applications/*/*.app/Contents/Resources/*.help/Contents/Info.plist",
        "/System/Library/CoreServices/*.app/Contents/Info.plist",
        "/System/Library/Extensions/*.kext/Contents/Info.plist",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/Info.plist",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/PlugIns/*.plugin/Contents/Info.plist",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/Resources/*.bundle/Contents/Info.plist",
        "/System/Library/Extensions/*.kext/Contents/Resources/*.bundle/Contents/Info.plist",
        "/System/Library/Extensions/*.kext/PlugIns/*.kext/Info.plist",
        "/System/Library/Filesystems/*/*.kext/Contents/Info.plist",
        "/System/Library/Filesystems/*/Encodings/*.kext/Contents/Info.plist",
        "/System/Library/Frameworks/*.framework/Versions/A/Resources/Info.plist",
        "/System/Library/PrivateFrameworks/*.framework/Versions/A/Resources/*.kext/Contents/Info.plist",
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
        if not (self.files):
            raise UnsupportedPluginError("No contents info files found")

    @export(record=DynamicDescriptor(["string"]))
    def contents_info(self) -> Iterator[DynamicDescriptor]:
        """Yield contents info information."""
        yield from build_records(self, "macos/contents_info", self.files)
