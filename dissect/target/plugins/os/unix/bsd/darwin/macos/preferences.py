from __future__ import annotations

import plistlib
from datetime import datetime
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


PreferenceRecord = TargetRecordDescriptor(
    "macos/preferences/entry",
    [
        ("string", "plist_name"),
        ("string", "key_path"),
        ("string", "value_type"),
        ("string", "value"),
        ("path", "source"),
    ],
)

PreferencePlistRecord = TargetRecordDescriptor(
    "macos/preferences/plist",
    [
        ("string", "plist_name"),
        ("varint", "entry_count"),
        ("string", "top_level_keys"),
        ("path", "source"),
    ],
)


def _flatten_plist(data, prefix=""):
    """Recursively flatten a plist dict into (key_path, value_type, value) tuples."""
    if isinstance(data, dict):
        for key, val in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            yield from _flatten_plist(val, full_key)
    elif isinstance(data, list):
        for i, val in enumerate(data):
            full_key = f"{prefix}[{i}]"
            yield from _flatten_plist(val, full_key)
    elif isinstance(data, bytes):
        # Truncate large binary blobs
        if len(data) <= 256:
            yield (prefix, "bytes", data.hex())
        else:
            yield (prefix, "bytes", f"<{len(data)} bytes>")
    elif isinstance(data, datetime):
        yield (prefix, "datetime", data.isoformat())
    elif isinstance(data, bool):
        yield (prefix, "bool", str(data))
    elif isinstance(data, int):
        yield (prefix, "int", str(data))
    elif isinstance(data, float):
        yield (prefix, "float", str(data))
    elif isinstance(data, str):
        yield (prefix, "string", data)
    else:
        yield (prefix, type(data).__name__, str(data))


class MacOSPreferencesPlugin(Plugin):
    """Plugin to parse macOS preference plist files.

    Parses all .plist files from both user and system preference directories
    and flattens them into key-value records with dot-notation paths.

    Locations:
    - ~/Library/Preferences/ (per-user preferences)
    - /Library/Preferences/ (system-wide preferences)

    Usage::

        target-query --plugin-path plugins -f preferences.entries <target>
        target-query --plugin-path plugins -f preferences.list <target>
    """

    __namespace__ = "preferences"

    PREFS_GLOBS = [
        "Users/*/Library/Preferences/*.plist",
        "Library/Preferences/*.plist",
    ]

    def __init__(self, target):
        super().__init__(target)
        self._plist_paths = []
        for glob_pattern in self.PREFS_GLOBS:
            self._plist_paths.extend(self.target.fs.path("/").glob(glob_pattern))
        self._plist_paths.sort()

    def check_compatible(self) -> None:
        if not self._plist_paths:
            raise UnsupportedPluginError("No preference plists found")

    def _read_plist(self, path):
        try:
            with path.open("rb") as fh:
                return plistlib.loads(fh.read())
        except Exception:
            return None

    # ── List all plists ──────────────────────────────────────────────────

    @export(record=PreferencePlistRecord)
    def list(self) -> Iterator[PreferencePlistRecord]:
        """List all preference plist files with their top-level keys."""
        for plist_path in self._plist_paths:
            try:
                data = self._read_plist(plist_path)
                if data is None:
                    continue

                plist_name = plist_path.name
                if isinstance(data, dict):
                    top_keys = ", ".join(sorted(data.keys())[:20])
                    count = len(data)
                else:
                    top_keys = type(data).__name__
                    count = 1

                yield PreferencePlistRecord(
                    plist_name=plist_name,
                    entry_count=count,
                    top_level_keys=top_keys,
                    source=plist_path,
                    _target=self.target,
                )
            except Exception as e:
                self.target.log.warning("Error listing plist %s: %s", plist_path, e)

    # ── All entries (flattened key-value) ─────────────────────────────────

    @export(record=PreferenceRecord)
    def entries(self) -> Iterator[PreferenceRecord]:
        """Parse all preference plists into flattened key-value records."""
        for plist_path in self._plist_paths:
            plist_name = plist_path.name
            try:
                data = self._read_plist(plist_path)
                if data is None:
                    continue

                for key_path, value_type, value in _flatten_plist(data):
                    yield PreferenceRecord(
                        plist_name=plist_name,
                        key_path=key_path,
                        value_type=value_type,
                        value=str(value),
                        source=plist_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing plist %s: %s", plist_path, e)
