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

ResourcesInfoStringsRecord = TargetRecordDescriptor(
    "macos/resources_info_strings",
    [
        ("string", "cf_bundle_name"),
        ("string", "cf_bundle_display_name"),
        ("string", "cf_bundle_identifier"),
        ("string", "cf_bundle_version"),
        ("string", "cf_bundle_package_type"),
        ("string", "cf_bundle_signature"),
        ("string", "cf_bundle_executable"),
        ("string[]", "cf_bundle_document_types"),
        ("string", "cf_bundle_short_version_string"),
        ("string", "ls_minimum_system_version"),
        ("string", "ns_human_readable_copyright"),
        ("string", "ns_main_nib_file"),
        ("string", "ns_principal_class"),
        ("path", "source"),
    ],
)

ResourcesInfoStringsRecords = (ResourcesInfoStringsRecord,)

FIELD_MAPPINGS = {
    "CFBundleName": "cf_bundle_name",
    "CFBundleDisplayName": "cf_bundle_display_name",
    "CFBundleIdentifier": "cf_bundle_identifier",
    "CFBundleVersion": "cf_bundle_version",
    "CFBundlePackageType": "cf_bundle_package_type",
    "CFBundleSignature": "cf_bundle_signature",
    "CFBundleExecutable": "cf_bundle_executable",
    "CFBundleDocumentTypes": "cf_bundle_document_types",
    "CFBundleShortVersionString ": "cf_bundle_short_version_string",
    "LSMinimumSystemVersion": "ls_minimum_system_version",
    "NSHumanReadableCopyright": "ns_human_readable_copyright",
    "NSMainNibFile": "ns_main_nib_file",
    "NSPrincipalClass": "ns_principal_class",
}


class ResourcesInfoStringsPlugin(Plugin):
    """macOS Resources InfoPlist.strings plugin.

    Parser localized bundle metadata for the Info.plist file.

    References:
        - https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleTypes/BundleTypes.html
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = find_bundle_files(self.target, "InfoPlist.strings")

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError("No Resources InfoPlist.strings files found")

    @export(record=ResourcesInfoStringsRecords)
    def resources_info_strings(self) -> Iterator[ResourcesInfoStringsRecords]:
        """Return Resources InfoPlist.strings information.

        Yields ResourcesInfoStringsRecords with the following fields:

        .. code-block:: text

            cf_bundle_name (string): Short name for the bundle.
            cf_bundle_display_name (string): Localized version of the application name.
            cf_bundle_identifier (string): Identifies the application to the system.
            cf_bundle_version (string): Specifies the build version number of the bundle.
            cf_bundle_package_type (string): Type of bundle.
            cf_bundle_signature (string): Creator code for the bundle.
            cf_bundle_executable (string): Name of the main executable file.
            cf_bundle_document_types (string[]): Document types supported by the application.
            cf_bundle_short_version_string (string): Release version of the application.
            ls_minimum_system_version (string): Minimum version of macOS required
                for this application to run.
            ns_human_readable_copyright (string): Copyright notice for the application.
            ns_main_nib_file (string): The nib file to load when the application is launched
                (without the .nib filename extension).
            ns_principal_class (string): Entry point for dynamically loaded Objective-C code.
            source (path): Path to the com.apple.airport.preferences.plist file.
        """
        yield from build_plist_records(
            self,
            self.files,
            ResourcesInfoStringsRecords,
            field_mappings=FIELD_MAPPINGS,
        )
