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
        ("string", "relevance_platform"),
        ("string", "build_version"),
        ("string", "cf_bundle_short_version_string"),
        ("string", "cf_bundle_version"),
        ("string", "project_name"),
        ("string", "source_version"),
        ("path", "source"),
    ],
)


ContentsVersionRecords = (ContentsVersionRecord,)

FIELD_MAPPINGS = {
    "BuildAliasOf": "build_alias_of",
    "RelevancePlatform": "relevance_platform",
    "BuildVersion": "build_version",
    "CFBundleShortVersionString": "cf_bundle_short_version_string",
    "CFBundleVersion": "cf_bundle_version",
    "ProjectName": "project_name",
    "SourceVersion": "source_version",
}


class ContentsVersionPlugin(Plugin):
    """macOS Contents version.plist file."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self.files = find_bundle_files(self.target, "version.plist")

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError("No contents version.plist files found")

    @export(record=ContentsVersionRecord)
    def contents_version(self) -> Iterator[ContentsVersionRecord]:
        """Yield contents version.plist information."""
        yield from build_plist_records(self, self.files, ContentsVersionRecords, field_mappings=FIELD_MAPPINGS)
