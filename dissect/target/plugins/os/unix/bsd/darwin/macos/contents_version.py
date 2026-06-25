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

ContentsVersionRecord = TargetRecordDescriptor(
    "macos/contents_version",
    [
        ("string", "build_alias_of"),
        ("varint", "build_version"),
        ("string", "cf_bundle_short_version_string"),
        ("string", "cf_bundle_version"),
        ("string", "project_name"),
        ("varint", "source_version"),
        ("path", "source"),
    ],
)


ContentsVersionRecords = (ContentsVersionRecord,)

FIELD_MAPPINGS = {
    "BuildAliasOf": "build_alias_of",
    "BuildVersion": "build_version",
    "CFBundleShortVersionString": "cf_bundle_short_version_string",
    "CFBundleVersion": "cf_bundle_version",
    "ProjectName": "project_name",
    "SourceVersion": "source_version",
}


class ContentsVersionPlugin(Plugin):
    """macOS contents version plugin.

    The version.plist file is a property list found in macOS bundles.

    References:
    - https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleversion
    - https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleshortversionstring
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self.files = find_bundle_files(self.target, "version.plist")

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError("No contents version.plist files found")

    @export(record=ContentsVersionRecord)
    def contents_version(self) -> Iterator[ContentsVersionRecord]:
        """Return macOS version.plist entries.

        Yields ContentsVersionRecord with the following fields:

        .. code-block:: text

            build_alias_of (string): Name of another component this entry is associated with.
            build_version (varint): Build version number.
            cf_bundle_short_version_string (string): The release or version number of the bundle.
            cf_bundle_version (string): The version of the build that identifies an iteration of the bundle.
            project_name (string): Project name.
            source_version (varint): Internal source version.
            source (path): Path to the version.plist file.
        """
        yield from build_plist_records(self, self.files, ContentsVersionRecords, field_mappings=FIELD_MAPPINGS)
