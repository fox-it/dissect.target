from __future__ import annotations

import json
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


WindowsSettingsCacheRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "os/windows/appdata/packages/settingscache",
    [
        ("string", "ParsingName"),
        ("string", "ActivationContext"),
        ("string", "SmallLogoPath"),
        ("string", "PageID"),
        ("string", "SettingID"),
        ("string", "HostID"),
        ("string", "Condition"),
        ("string", "Comment"),
        ("string", "CacheFilePath"),
    ],
)


def normalize_none(input: str | list) -> str | list | None:
    return None if input in ("", "N/A", "[]", []) else input


class settings_cache(Plugin):
    """Extract Windows SettingsCache records (Windows 10 only for now; may not work on Windows 11)."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.cachefiles = []

        for user_details in target.user_details.all_with_home():
            full_path = user_details.home_path.joinpath("AppData/Local/Packages")
            # path location for windows 10. windows 11 path not implemented yet.
            cache_files = full_path.glob("Microsoft.Windows.Search_*/LocalState/DeviceSearchCache/SettingsCache.txt")
            for cache_file in cache_files:
                if cache_file.exists():
                    self.cachefiles.append((user_details.user, cache_file))

    def check_compatible(self) -> None:
        if len(self.cachefiles) == 0:
            raise UnsupportedPluginError("No SettingsCache files found")

    @export(record=WindowsSettingsCacheRecord)
    def settingscache(self) -> Iterator[WindowsSettingsCacheRecord]:
        """Return Windows Search AppCache records for all users.

        Yields `WindowsSettingsCacheRecord` with the following fields:

            ParsingName (string): Internal parsing name of the cached item.
            ActivationContext (string): Activation context associated with the item.
            SmallLogoPath (string): Path to the small logo image for the tile.
            PageID (string): Page identifier for the tile.
            SettingID (string): Identifier for the setting tied to the item.
            HostID (string): Host identifier for the system or app related to the item.
            Condition (string): Condition of the setting or tile.
            Comment (string): Comment or description attached to the item.
            CacheFilePath (path): Path to the cache file from which this record is extracted.

        Notes:
            - Empty, "N/A", or invalid entries (such as empty lists) are normalized to `None`.
            - Timestamps are converted from Windows FILETIME format using `wintimestamp`.
            - If a cache file cannot be parsed (e.g., due to invalid JSON format), a warning is logged,
                and processing continues.
        """
        for user, cache_file in self.cachefiles:
            with cache_file.open("r", encoding="utf-8") as cachefileIO:
                try:
                    entries = json.load(cachefileIO)
                except json.JSONDecodeError as e:
                    self.target.log.warning("Failed to parse %s: %s", cache_file, e)
                    continue

            for entry in entries:
                yield WindowsSettingsCacheRecord(
                    ParsingName=normalize_none(entry.get("System.ParsingName", {}).get("Value")),
                    ActivationContext=normalize_none(
                        entry.get("System.AppUserModel.ActivationContext", {}).get("Value")
                    ),
                    SmallLogoPath=normalize_none(entry.get("System.Tile.SmallLogoPath", {}).get("Value")),
                    PageID=normalize_none(entry.get("System.Setting.PageID", {}).get("Value")),
                    SettingID=normalize_none(entry.get("System.Setting.SettingID", {}).get("Value")),
                    HostID=normalize_none(entry.get("System.Setting.HostID", {}).get("Value")),
                    Condition=normalize_none(entry.get("System.Setting.Condition", {}).get("Value")),
                    Comment=normalize_none(entry.get("System.Comment", {}).get("Value")),
                    CacheFilePath=cache_file,
                    _target=self.target,
                    _user=user,
                )
