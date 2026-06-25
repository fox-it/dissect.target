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

HashRecord = TargetRecordDescriptor(
    "macos/code_signature_coderesources/hash",
    [
        ("string", "hash"),
        ("boolean", "optional"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

HashTwoRecord = TargetRecordDescriptor(
    "macos/code_signature_coderesources/hash_two",
    [
        ("string", "hash2"),
        ("boolean", "optional"),
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
    HashRecord,
    HashTwoRecord,
    CDHashRecord,
)

FIELD_MAPPINGS = {
    "Resources_PROMISE_icns": "resources_promise_icns",
}


class CodeSignatureCodeResourcesPlugin(Plugin):
    """macOS Code signature CodeResources plugin.


    _CodeSignature/CodeResources files are part of the macOS code
    signing system and store metadata about signed resources within an
    application bundle. They contains hashes and rules used to verify the
    integrity of code and resources during code signature validation.

    References:
        - https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/AboutCS/AboutCS.html
        - https://developer.apple.com/documentation/endpointsecurity/es_process_t/cdhash
        - https://alfiecg.uk/2024/01/06/Ad-hoc-signing.html
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = find_bundle_files(self.target, "/_CodeSignature/CodeResources")

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No code signature coderesources files found")

    @export(record=CodeSignatureCodeResourcesRecords)
    def code_signature_coderesources(self) -> Iterator[CodeSignatureCodeResourcesRecords]:
        """Return macOS CodeResources plist entries.

        Yields the following record types:

        .. code-block:: text

            OmitRecord:
                omit (boolean): Flag indicating the entry is marked as omitted.
                weight (varint): Priority over other resources.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the CodeResources file.

            NestedRecord:
                nested (boolean): Flag indicating the entry may be associated with nested code,
                    such as libraries, helper tools, and other bits of code that are embedded in the app.
                weight (varint): Priority over other resources.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the CodeResources file.

            OptionalRecord:
                optional (boolean)
                weight (varint): Priority over other resources.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the CodeResources file.

            HashRecord:
                hash (string): Hash value.
                optional (boolean): Flag indicating the entry is marked as optional.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the CodeResources file.

            HashTwoRecord:
                hash2 (string): Secondary hash value.
                optional (boolean): Flag indicating the entry is marked as optional.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the CodeResources file.

            CDHashRecord:
                cdhash (string): The code directory hash value.
                requirement (string): Code signing requirement.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the CodeResources file.
        """
        yield from build_plist_records(
            self, self.files, CodeSignatureCodeResourcesRecords, field_mappings=FIELD_MAPPINGS
        )
