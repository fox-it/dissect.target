from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SpotlightShortcutRecord = TargetRecordDescriptor(
    "macos/spotlightshortcuts/entries",
    [
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)


class MacOSSpotlightShortcutsPlugin(Plugin):
    """Plugin to parse macOS Spotlight shortcuts and search preferences.

    Locations:
        ~/Library/Application Support/com.apple.spotlight.Shortcuts
        ~/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts.plist
        ~/Library/Preferences/com.apple.Spotlight.plist
    """

    __namespace__ = "spotlightshortcuts"

    GLOBS = [
        "Users/*/Library/Application Support/com.apple.spotlight.Shortcuts",
        "Users/*/Library/Application Support/com.apple.spotlight/com.apple.spotlight.Shortcuts.plist",
        "Users/*/Library/Preferences/com.apple.Spotlight.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._plist_paths = []
        root = self.target.fs.path("/")
        for pattern in self.GLOBS:
            self._plist_paths.extend(root.glob(pattern))

    def check_compatible(self) -> None:
        if not self._plist_paths:
            raise UnsupportedPluginError("No Spotlight shortcuts or preferences found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    def _flatten(self, data, prefix=""):
        """Recursively flatten plist data into key-value pairs."""
        results = []
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(value, dict):
                    results.extend(self._flatten(value, full_key))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, (dict, list)):
                            results.extend(self._flatten(item, f"{full_key}[{i}]"))
                        else:
                            results.append((full_key, str(item)))
                else:
                    results.append((full_key, str(value)))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                item_key = f"{prefix}[{i}]" if prefix else f"[{i}]"
                if isinstance(item, (dict, list)):
                    results.extend(self._flatten(item, item_key))
                else:
                    results.append((item_key, str(item)))
        return results

    @export(record=SpotlightShortcutRecord)
    def entries(self) -> Iterator[SpotlightShortcutRecord]:
        """Parse Spotlight shortcuts and search preferences."""
        for path in self._plist_paths:
            try:
                data = self._read_plist(path)
                if data is None:
                    continue

                pairs = self._flatten(data)
                for key, value in pairs:
                    yield SpotlightShortcutRecord(
                        key=key,
                        value=value,
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing Spotlight shortcuts %s: %s", path, e)
