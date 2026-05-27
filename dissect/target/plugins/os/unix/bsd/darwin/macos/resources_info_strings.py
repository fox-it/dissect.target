from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import find_bundle_files
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_plist_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


class ResourcesInfoStringsPlugin(Plugin):
    """macOS Resources InfoPlist.strings plist file."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = find_bundle_files(self.target, "InfoPlist.strings")

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError("No Resources InfoPlist.strings files found")

    @export(record=DynamicDescriptor(["string"]))
    def resources_info_strings(self) -> Iterator[DynamicDescriptor]:
        """Yield Resources InfoPlist.strings information."""
        yield from build_plist_records(self, self.files, function_name="macos/resources_info_strings")
