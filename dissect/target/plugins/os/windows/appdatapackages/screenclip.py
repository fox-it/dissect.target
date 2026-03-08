from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


WindowsScreenClipJsonRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "os/windows/appdata/packages/screenclip/json",
    [
        ("string[]", "clipPoints"),
        ("string", "appActivityId"),
        ("string", "appDisplayName"),
        ("string", "activationUrl"),
        ("boolean", "isRoamable"),
        ("string", "visualElements"),
        ("string[]", "cross_platform_identifiers"),
        ("string", "description"),
        ("string", "contentUrl"),
        ("string", "contentInfo"),
        ("string", "CacheFilePath"),
    ],
)
WindowsScreenClipPngRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "os/windows/appdata/packages/screenclip/png",
    [
        ("string", "sha256Hash"),
        ("string", "sha1Hash"),
        ("string", "md5Hash"),
        ("string", "CacheFilePath"),
    ],
)


def normalize_none(input: str | list) -> str | list | None:
    return None if input in ("", "N/A", "[]", []) else input


class settings_cache(Plugin):
    """Extract Windows screenclip records (Windows 10 only for now; may not work on Windows 11)."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.jsonfiles = []
        self.pngfiles = []

        for user_details in target.user_details.all_with_home():
            full_path = user_details.home_path.joinpath("AppData/Local/Packages")
            json_files = full_path.glob("MicrosoftWindows.Client.CBS_*/TempState/ScreenClip/*.json")
            for json_file in json_files:
                if json_file.exists():
                    self.jsonfiles.append((user_details.user, json_file))
            png_files = full_path.glob("MicrosoftWindows.Client.CBS_*/TempState/ScreenClip/*.png")
            for png_file in png_files:
                if png_file.exists():
                    self.pngfiles.append((user_details.user, png_file))

    def check_compatible(self) -> None:
        if len(self.jsonfiles) == 0 and len(self.pngfiles) == 0:
            raise UnsupportedPluginError("No screenclip files found")

    @export(record=WindowsScreenClipJsonRecord)
    def screenclip(self) -> Iterator[WindowsScreenClipJsonRecord]:
        """Yield Windows ScreenClip JSON and PNG records for all users.

        JSON Records (`WindowsScreenClipJsonRecord`):
            clipPoints (string[]): Coordinates of the captured area as "x,y" strings.
            appActivityId (string): The unique identifier of the app activity.
            appDisplayName (string): Display name of the application associated with the clip.
            activationUrl (string): URL used to activate or open the app activity.
            isRoamable (boolean): Whether the activity can roam across devices.
            visualElements (string): JSON or string representing visual properties of the clip.
            cross_platform_identifiers (string[]): Identifiers linking the activity across platforms.
            description (string): Description or note associated with the clip.
            contentUrl (string): URL of the clip content, if any.
            contentInfo (string): Additional information about the clip content.
            CacheFilePath (string): Path to the source JSON file.

        PNG Records (`WindowsScreenClipPngRecord`):
            md5Hash (string): MD5 hash of the PNG data.
            sha1Hash (string): SHA1 hash of the PNG data.
            sha256Hash (string): SHA256 hash of the PNG data.
            CacheFilePath (string): Path to the source PNG file.

        Notes:
            - Empty, "N/A", or invalid entries (such as empty lists) are normalized to `None`.
            - PNG records are hashed to uniquely identify the clip content.
            - JSON 'userActivity' fields may be nested; invalid or unparsable JSON is skipped with a warning.
        """
        for user, json_cache_file in self.jsonfiles:
            with json_cache_file.open("r", encoding="utf-8") as cachefileIO:
                try:
                    parsed_json = json.load(cachefileIO)
                except json.JSONDecodeError as e:
                    self.target.log.warning("Failed to parse %s: %s", json_cache_file, e)
                    continue
            # Parse the escaped 'userActivity' JSON string
            try:
                user_activity = json.loads(parsed_json.get("userActivity", "{}"))
            except json.JSONDecodeError:
                user_activity = {}

            yield WindowsScreenClipJsonRecord(
                clipPoints=[f"{pt['x']},{pt['y']}" for pt in parsed_json.get("clipPoints", [])],
                appActivityId=normalize_none(user_activity.get("appActivityId")),
                appDisplayName=normalize_none(user_activity.get("appDisplayName")),
                activationUrl=normalize_none(user_activity.get("activationUrl")),
                isRoamable=user_activity.get("isRoamable", False),
                visualElements=normalize_none(user_activity.get("visualElements")),
                cross_platform_identifiers=normalize_none(user_activity.get("cross-platform-identifiers", [])),
                description=normalize_none(user_activity.get("description")),
                contentUrl=normalize_none(user_activity.get("contentUrl")),
                contentInfo=normalize_none(user_activity.get("contentInfo")),
                CacheFilePath=json_cache_file,
                _target=self.target,
                _user=user,
            )

        for user, png_cache_file in self.pngfiles:
            with png_cache_file.open("rb") as png_data:
                data = png_data.read()

                md5_hash = hashlib.md5(data).hexdigest()
                sha1_hash = hashlib.sha1(data).hexdigest()
                sha256_hash = hashlib.sha256(data).hexdigest()

                yield WindowsScreenClipPngRecord(
                    md5Hash=md5_hash,
                    sha1Hash=sha1_hash,
                    sha256Hash=sha256_hash,
                    CacheFilePath=json_cache_file,
                    _target=self.target,
                    _user=user,
                )
