from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.plist import build_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\&gt;\&lt;]")

ContentsVersionRecord = TargetRecordDescriptor(
    "macos/contents_version",
    [
        ("string", "BuildAliasOf"),
        ("string", "RelevancePlatform"),
        ("string", "BuildVersion"),
        ("string", "CFBundleShortVersionString"),
        ("string", "CFBundleVersion"),
        ("string", "ProjectName"),
        ("string", "SourceVersion"),
        ("path", "source"),
    ],
)


ContentsVersionRecords = (ContentsVersionRecord,)


class MacOSContentsVersionPlugin(Plugin):
    """macOS Contents version.plist file."""

    PATHS = (
        "/Applications/*/*.app/Contents/version.plist",
        "/Applications/*/*.app/Contents/Resources/*.help/Contents/version.plist",
        "/System/Library/CoreServices/*.app/Contents/version.plist",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/version.plist",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/PlugIns/*.plugin/Contents/version.plist",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/Resources/*.bundle/Contents/version.plist",
        "/System/Library/Extensions/*.kext/Contents/Resources/*.bundle/Contents/version.plist",
        "/System/Library/Extensions/*.kext/Contents/version.plist",
        "/System/Library/Extensions/*.kext/PlugIns/*.kext/version.plist",
        "/System/Library/Filesystems/*/*.kext/Contents/version.plist",
        "/System/Library/Filesystems/*/Encodings/*.kext/Contents/version.plist",
        "/System/Library/Frameworks/*.framework/Versions/A/Resources/version.plist",
        "/System/Library/PrivateFrameworks/*.framework/Versions/A/Resources/*.kext/Contents/version.plist",
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
            raise UnsupportedPluginError("No contents version.plist files found")

    @export(record=ContentsVersionRecord)
    def contents_version(self) -> Iterator[ContentsVersionRecord]:
        """Yield contents version.plist information."""
        yield from build_records(self, "macos/contents_version", self.files, ContentsVersionRecords)
