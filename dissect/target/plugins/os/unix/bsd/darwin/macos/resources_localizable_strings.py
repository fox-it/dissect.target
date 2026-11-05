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


class ResourcesLocalizableStringsPlugin(Plugin):
    """macOS Resources Localizable.strings plist file.

    Parses resource files used to store text that can be translated into different languages.

    References:
        - https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/LoadingResources/Strings/Strings.html
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = find_bundle_files(self.target, "Localizable.strings")

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError("No Resources Localizable.strings files found")

    @export(record=DynamicDescriptor(["string"]))
    def resources_localizable_strings(self) -> Iterator[DynamicDescriptor]:
        """Yield Resources Localizable.strings information."""
        yield from build_plist_records(self, self.files, function_name="macos/resources_localizable_strings")
