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
        ("string", "GroupID"),
        ("string", "HostID"),
        ("string", "Condition"),
        ("string", "FontFamily"),
        ("string", "Glyph"),
        ("string", "GlyphRtl"),
        ("string", "HighKeywords"),
        ("string", "Comment"),
        ("string", "CacheFilePath"),
    ],
)


def normalize_none(value):
    if value in ("", "N/A", "[]", [], None):
        return None
    return value


class settings_cache(Plugin):
    """Extract Windows Search SettingsCache records."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.cachefiles = []

        for user_details in target.user_details.all_with_home():
            full_path = user_details.home_path.joinpath("AppData/Local/Packages")

            cache_files = full_path.glob(
                "Microsoft.Windows.Search_*/LocalState/DeviceSearchCache/SettingsCache.txt"
            )

            for cache_file in cache_files:
                self.cachefiles.append((user_details.user, cache_file))

    def check_compatible(self) -> None:
        if not self.cachefiles:
            raise UnsupportedPluginError("No SettingsCache files found")

    @export(record=WindowsSettingsCacheRecord)
    def settingscache(self) -> Iterator[WindowsSettingsCacheRecord]:
        """Return Windows Search SettingsCache records for all users.

        Fields:
            ParsingName: Internal parsing name of the settings entry
            ActivationContext: Command executed when the setting launches
            SmallLogoPath: Path to the tile logo
            PageID: Settings page identifier
            SettingID: Identifier for the setting
            GroupID: Settings group identifier
            HostID: GUID identifying the host component
            Condition: Visibility condition
            FontFamily: Font used for glyph
            Glyph: Icon glyph
            GlyphRtl: RTL glyph icon
            HighKeywords: Search keywords for the setting
            Comment: Human-readable description
            CacheFilePath: Source cache file
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
                    GroupID=normalize_none(entry.get("System.Setting.GroupID", {}).get("Value")),
                    HostID=normalize_none(entry.get("System.Setting.HostID", {}).get("Value")),
                    Condition=normalize_none(entry.get("System.Setting.Condition", {}).get("Value")),
                    FontFamily=normalize_none(entry.get("System.Setting.FontFamily", {}).get("Value")),
                    Glyph=normalize_none(entry.get("System.Setting.Glyph", {}).get("Value")),
                    GlyphRtl=normalize_none(entry.get("System.Setting.GlyphRtl", {}).get("Value")),
                    HighKeywords=normalize_none(entry.get("System.HighKeywords", {}).get("Value")),
                    Comment=normalize_none(entry.get("System.Comment", {}).get("Value")),
                    CacheFilePath=cache_file,
                    _target=self.target,
                    _user=user,
                )