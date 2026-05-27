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


class ContentsInfoPlugin(Plugin):
    """macOS contents info plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = find_bundle_files(self.target, "Info.plist")

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No contents info files found")

    @export(record=DynamicDescriptor(["string"]))
    def contents_info(self) -> Iterator[DynamicDescriptor]:
        """Yield contents info information."""
        yield from build_plist_records(self, self.files, function_name="macos/contents_info")
