from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

KeyboardLayoutRecord = TargetRecordDescriptor(
    "macos/keyboard_layout",
    [
        ("string", "input_source_kind"),
        ("string", "keyboard_layout_name"),
        ("varint", "keyboard_layout_id"),
        ("boolean", "enabled_layout"),
        ("boolean", "selected_layout"),
        ("boolean", "current_layout"),
        ("path", "source"),
    ],
)


class KeyboardLayoutPlugin(Plugin):
    """macOS keyboard layout plugin."""

    PATH = "/Library/Preferences/com.apple.HIToolbox.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = None
        self._resolve_file()

    def _resolve_file(self) -> None:
        path = self.target.fs.path(self.PATH)
        if path.exists():
            self.file = path

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No com.apple.HIToolbox.plist file found")

    @export(record=KeyboardLayoutRecord)
    def keyboard_layout(self) -> Iterator[KeyboardLayoutRecord]:
        """Yield macOS keyboard layout information."""
        plist = plistlib.loads(self.file.read_bytes())

        for source in plist.get("AppleEnabledInputSources", []):
            yield KeyboardLayoutRecord(
                input_source_kind=source.get("InputSourceKind"),
                keyboard_layout_name=source.get("KeyboardLayout Name"),
                keyboard_layout_id=source.get("KeyboardLayout ID"),
                enabled_layout=True,
                selected_layout=source in plist.get("AppleSelectedInputSources", []),
                current_layout=(
                    source.get("KeyboardLayout ID") == plist.get("AppleCurrentKeyboardLayoutInputSourceID")
                ),
                source=self.file,
                _target=self.target,
            )
