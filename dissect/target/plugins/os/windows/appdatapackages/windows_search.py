from __future__ import annotations

import json
from typing import TYPE_CHECKING

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


WindowsSearchRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "os/windows/appdatapackages/windows_search_record",
    [
        ("string", "FileExtension"),
        ("string", "ProductVersion"),
        ("boolean", "IsSystemComponent"),
        ("string", "Kind"),
        ("string", "ParsingName"),
        ("varint", "TimesUsed"),
        ("varint", "Background"),
        ("string", "PackageFullName"),
        ("string", "Identity"),
        ("string", "FileName"),
        ("string", "JumpList"),
        ("string", "VoiceCommandExamples"),
        ("string", "ItemType"),
        ("datetime", "DateAccessed"),
        ("string", "EncodedTargetPath"),
        ("string", "SmallLogoPath"),
        ("string", "ItemNameDisplay"),
        ("string", "CacheFilePath"),
    ],
)


def normalize_none(string: str | list) -> str | list | None:
    return None if string in ("", "N/A", "[]", []) else string


class WindowsSearch(Plugin):
    """Extract Windows Search AppCache records (Windows 10 only; may not work on Windows 11)."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.cachefiles = []

        for user_details in target.user_details.all_with_home():
            full_path = user_details.home_path.joinpath("AppData/Local/Packages")
            cache_files = full_path.glob("Microsoft.Windows.Search_*/LocalState/DeviceSearchCache/AppCache*.txt")
            for cache_file in cache_files:
                if cache_file.exists():
                    self.cachefiles.append((user_details.user, cache_file))

    def check_compatible(self) -> None:
        if len(self.cachefiles) == 0:
            raise UnsupportedPluginError("No AppCache files found")

    @export(record=WindowsSearchRecord)
    def appcache(self) -> Iterator[WindowsSearchRecord]:
        """Return Windows Search AppCache records for all users.

        Yields WindowsSearchRecord with the following fields:

            FileExtension (string): The file extension of the cached item.
            ProductVersion (string): Version of the software related to the item.
            IsSystemComponent (bool): Whether the item is a system component.
            Kind (string): Kind/type of the item.
            ParsingName (string): Internal parsing name of the item.
            TimesUsed (varint): Number of times the item has been used.
            Background (varint): Tile background type.
            PackageFullName (string): Full package name of the app.
            Identity (string): Identity string of the app/item.
            FileName (string): Name of the file.
            JumpList (list): List of jump list entries associated with the item.
            VoiceCommandExamples (list): Examples of voice commands linked to the item.
            ItemType (string): Item type description.
            DateAccessed (datetime): Timestamp of last access (converted from Windows FILETIME).
            EncodedTargetPath (string): Encoded target path of the tile.
            SmallLogoPath (string): Path to the small logo image.
            ItemNameDisplay (string): Display name of the item.
            CacheFilePath (path): Path to the cache file where this record came from.

        Notes:
            - If a JSON cache file cannot be parsed, a warning is logged and processing continues.
            - Fields with empty strings, "N/A", empty lists, or None are normalized to None.
            - Timestamps are converted from Windows FILETIME format using `wintimestamp`.
        """
        for user, cache_file in self.cachefiles:
            with cache_file.open("r", encoding="utf-8") as cachefileIO:
                try:
                    entries = json.load(cachefileIO)
                except json.JSONDecodeError as e:
                    self.target.log.warning("Failed to parse %s: %s", cache_file, e)
                    continue

            for entry in entries:
                yield WindowsSearchRecord(
                    FileExtension=normalize_none(entry.get("System.FileExtension", {}).get("Value")),
                    ProductVersion=normalize_none(entry.get("System.Software.ProductVersion", {}).get("Value")),
                    IsSystemComponent=entry.get("System.AppUserModel.IsSystemComponent", {}).get("Value"),
                    Kind=normalize_none(entry.get("System.Kind", {}).get("Value")),
                    ParsingName=normalize_none(entry.get("System.ParsingName", {}).get("Value")),
                    TimesUsed=entry.get("System.Software.TimesUsed", {}).get("Value"),
                    Background=entry.get("System.Tile.Background", {}).get("Value"),
                    PackageFullName=normalize_none(entry.get("System.AppUserModel.PackageFullName", {}).get("Value")),
                    Identity=normalize_none(entry.get("System.Identity", {}).get("Value")),
                    FileName=normalize_none(entry.get("System.FileName", {}).get("Value")),
                    JumpList=normalize_none(entry.get("System.ConnectedSearch.JumpList", {}).get("Value", [])),
                    VoiceCommandExamples=normalize_none(
                        entry.get("System.ConnectedSearch.VoiceCommandExamples", {}).get("Value", [])
                    ),
                    ItemType=normalize_none(entry.get("System.ItemType", {}).get("Value")),
                    DateAccessed=wintimestamp(entry.get("System.DateAccessed", {}).get("Value")),
                    EncodedTargetPath=normalize_none(entry.get("System.Tile.EncodedTargetPath", {}).get("Value")),
                    SmallLogoPath=normalize_none(entry.get("System.Tile.SmallLogoPath", {}).get("Value")),
                    ItemNameDisplay=normalize_none(entry.get("System.ItemNameDisplay", {}).get("Value")),
                    CacheFilePath=cache_file,
                    _target=self.target,
                    _user=user,
                )
