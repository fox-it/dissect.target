from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.plist import build_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

re_illegal_characters = re.compile(r"[\(\): \.\-#\/\>\<]")

CodeSignatureCodeResourcesRecord1 = TargetRecordDescriptor(
    "macos/code_signature_coderesources",
    [
        ("boolean", "omit"),
        ("string", "weight"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

CodeSignatureCodeResourcesRecord2 = TargetRecordDescriptor(
    "macos/code_signature_coderesources",
    [
        ("boolean", "nested"),
        ("string", "weight"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

CodeSignatureCodeResourcesRecord3 = TargetRecordDescriptor(
    "macos/code_signature_coderesources",
    [
        ("string", "cdhash"),
        ("string", "requirement"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)


CodeSignatureCodeResourcesRecords = (
    CodeSignatureCodeResourcesRecord1,
    CodeSignatureCodeResourcesRecord2,
    CodeSignatureCodeResourcesRecord3,
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

    @export(record=DynamicDescriptor(["string"]))
    def code_signature_coderesources(self) -> Iterator[DynamicDescriptor]:
        """Yield code signature coderesources information."""
        yield from build_records(
            self, "macos/code_signature_coderesources", self.files, CodeSignatureCodeResourcesRecords
        )
