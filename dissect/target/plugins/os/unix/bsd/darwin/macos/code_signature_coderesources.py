from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import find_bundle_files
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

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

OptionalRecord = TargetRecordDescriptor(
    "macos/code_signature_coderesources/optional",
    [
        ("boolean", "optional"),
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
    OptionalRecord,
    CDHashRecord,
)

FIELD_MAPPINGS = {
    "Resources_PROMISE_icns": "resources_promise_icns",
}


class CodeSignatureCodeResourcesPlugin(Plugin):
    """macOS Code signature CodeResources plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = find_bundle_files(self.target, "/_CodeSignature/CodeResources")

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No code signature coderesources files found")

    @export(record=CodeSignatureCodeResourcesRecords)
    def code_signature_coderesources(self) -> Iterator[CodeSignatureCodeResourcesRecords]:
        """Yield code signature coderesources information."""
        yield from build_plist_records(
            self, self.files, CodeSignatureCodeResourcesRecords, field_mappings=FIELD_MAPPINGS
        )
