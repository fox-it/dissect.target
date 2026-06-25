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
    """macOS keyboard layout plugin.

    This plugin extracts information about the keyboard layouts of the system.
    """

    PATH = "/Library/Preferences/com.apple.HIToolbox.plist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No com.apple.HIToolbox.plist file found")

    @export(record=KeyboardLayoutRecord)
    def keyboard_layout(self) -> Iterator[KeyboardLayoutRecord]:
        """Return macOS keyboard layout information.

        Yields KeyboardLayoutRecord with the following fields:

        .. code-block:: text

            input_source_kind (string): Kind of the input source.
            keyboard_layout_name (string): Name of the keyboard layout.
            keyboard_layout_id (varint): ID of the keyboard layout.
            enabled_layout (boolean): Whether the layout is enabled.
            selected_layout (boolean): Whether the layout is selected.
            current_layout (boolean): Whether it is the current layout.
            source (path): Path to the com.apple.HIToolbox.plist file.
        """
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
