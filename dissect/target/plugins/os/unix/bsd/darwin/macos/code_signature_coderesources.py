from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")

OmitRecord = TargetRecordDescriptor(
    "macos/code_signature_coderesources/omit",
    [
        ("boolean", "omit"),
        ("varint", "weight"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

NestedRecord = TargetRecordDescriptor(
    "macos/code_signature_coderesources/nested",
    [
        ("boolean", "nested"),
        ("varint", "weight"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

CDHashRecord = TargetRecordDescriptor(
    "macos/code_signature_coderesources/cdhash",
    [
        ("string", "cdhash"),
        ("string", "requirement"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)


CodeSignatureCodeResourcesRecords = (
    OmitRecord,
    NestedRecord,
    CDHashRecord,
)


class CodeSignatureCodeResourcesPlugin(Plugin):
    """macOS Code signature CodeResources plugin."""

    PATHS = (
        "/Applications/Utilities/*.app/Contents/_CodeSignature/CodeResources",
        "/System/Library/CoreServices/*.app/Contents/_CodeSignature/CodeResources",
        "/System/Library/Extensions/*.kext/Contents/_CodeSignature/CodeResources",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/_CodeSignature/CodeResources",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/PlugIns/*.plugin/Contents/_CodeSignature/CodeResources",
        "/System/Library/Extensions/*.kext/Contents/PlugIns/*.kext/Contents/Resources/*.bundle/Contents/_CodeSignature/CodeResources",
        "/System/Library/Extensions/*.kext/Contents/Resources/*.bundle/Contents/_CodeSignature/CodeResources",
        "/System/Library/Filesystems/*/*.kext/Contents/_CodeSignature/CodeResources",
        "/System/Library/Filesystems/*/Encodings/*.kext/Contents/_CodeSignature/CodeResource",
        "/System/Library/PrivateFrameworks/*.framework/Versions/A/Resources/*.kext/Contents/_CodeSignature/CodeResources",
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
            raise UnsupportedPluginError("No code signature coderesources files found")

    @export(record=CodeSignatureCodeResourcesRecords)
    def code_signature_coderesources(self) -> Iterator[CodeSignatureCodeResourcesRecords]:
        """Yield code signature coderesources information."""
        yield from build_plist_records(self, self.files, CodeSignatureCodeResourcesRecords)
