from __future__ import annotations

from typing import TYPE_CHECKING
import json
from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


WindowsSearchRecord = TargetRecordDescriptor(
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
        ("string[]", "JumpList"),
        ("string[]", "VoiceCommandExamples"),
        ("string", "ItemType"),
        ("datetime", "DateAccessed"),
        ("string", "EncodedTargetPath"),
        ("string", "SmallLogoPath"),
        ("string", "ItemNameDisplay"),
    ],
)

def normalize_none(string: str):
    return None if string in ("", "N/A", "[]") else string


class WindowsSearch(Plugin):
    """Plugin that parses the Windows search json file under appdata. known to work on windows a few windows 10 machines, unknown oif works on other versions."""

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
        """
        """
        for user, cache_file in self.cachefiles:
            target_path = self.target.fs.path(cache_file)
            with target_path.open("r", encoding="utf-8") as f:
                try:
                    entries = json.load(f)
                except json.JSONDecodeError as e:
                    self.target.log.warning(f"Failed to parse {cache_file}: {e}")
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
                    JumpList=entry.get("System.ConnectedSearch.JumpList", {}).get("Value", []),
                    VoiceCommandExamples=entry.get("System.ConnectedSearch.VoiceCommandExamples", {}).get("Value", []),
                    ItemType=normalize_none(entry.get("System.ItemType", {}).get("Value")),
                    DateAccessed=from_unix(entry.get("System.DateAccessed", {}).get("Value")),
                    EncodedTargetPath=normalize_none(entry.get("System.Tile.EncodedTargetPath", {}).get("Value")),
                    SmallLogoPath=normalize_none(entry.get("System.Tile.SmallLogoPath", {}).get("Value")),
                    ItemNameDisplay=normalize_none(entry.get("System.ItemNameDisplay", {}).get("Value")),
                )