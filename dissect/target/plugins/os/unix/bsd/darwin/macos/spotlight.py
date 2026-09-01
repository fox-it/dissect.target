from __future__ import annotations

import plistlib
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


SpotlightAppRecord = TargetRecordDescriptor(
    "macos/spotlight/applist",
    [
        ("string", "display_name"),
        ("string", "bundle_id"),
        ("string", "app_url"),
        ("string", "app_path"),
        ("string", "identifier"),
        ("string[]", "display_name_initials"),
        ("path", "source"),
    ],
)


class SpotlightApplistPlugin(Plugin):
    """Plugin to parse Spotlight applist.dat.

    Parses application entries from the Spotlight application cache at:
    ~/Library/Application Support/com.apple.Spotlight/applist.dat

    This is an NSKeyedArchiver binary plist containing applications known
    to Spotlight, including display name, bundle ID, URL, and search initials.
    """

    __namespace__ = "spotlight"

    APPLIST_GLOB = "Users/*/Library/Application Support/com.apple.Spotlight/applist.dat"

    def __init__(self, target):
        super().__init__(target)
        self._paths = list(self.target.fs.path("/").glob(self.APPLIST_GLOB))

    def check_compatible(self) -> None:
        if not self._paths:
            raise UnsupportedPluginError("No Spotlight applist.dat files found")

    def _resolve_uid(self, objects, obj):
        """Resolve an NSKeyedArchiver UID reference."""
        if isinstance(obj, plistlib.UID):
            return objects[obj]
        return obj

    def _parse_applist(self, path):
        """Parse an NSKeyedArchiver applist.dat and yield app entry dicts."""
        try:
            with path.open("rb") as fh:
                data = plistlib.loads(fh.read())
        except Exception:
            return

        objects = data.get("$objects", [])

        for obj in objects:
            if not isinstance(obj, dict) or "bundleID" not in obj:
                continue

            display_name = self._resolve_uid(objects, obj.get("displayName", ""))
            bundle_id = self._resolve_uid(objects, obj.get("bundleID", ""))
            identifier = self._resolve_uid(objects, obj.get("identifier", ""))

            # Resolve URL (NSURL with NS.relative)
            url_raw = self._resolve_uid(objects, obj.get("URL", ""))
            if isinstance(url_raw, dict) and "NS.relative" in url_raw:
                app_url = str(self._resolve_uid(objects, url_raw["NS.relative"]))
            else:
                app_url = str(url_raw) if url_raw else ""

            # Convert file:// URL to a readable path
            app_path = ""
            if app_url.startswith("file://"):
                app_path = unquote(urlparse(app_url).path).rstrip("/")

            # Resolve displayNameInitials (NSArray of UIDs)
            initials_raw = self._resolve_uid(objects, obj.get("displayNameInitials", ""))
            initials = []
            if isinstance(initials_raw, dict) and "NS.objects" in initials_raw:
                initials = [str(self._resolve_uid(objects, u)) for u in initials_raw["NS.objects"]]

            yield {
                "display_name": str(display_name) if display_name else "",
                "bundle_id": str(bundle_id) if bundle_id else "",
                "app_url": app_url,
                "app_path": app_path,
                "identifier": str(identifier) if identifier else "",
                "initials": initials,
            }

    @export(record=SpotlightAppRecord)
    def applist(self) -> Iterator[SpotlightAppRecord]:
        """Parse Spotlight applist.dat for known applications."""
        for path in self._paths:
            try:
                for entry in self._parse_applist(path):
                    yield SpotlightAppRecord(
                        display_name=entry["display_name"],
                        bundle_id=entry["bundle_id"],
                        app_url=entry["app_url"],
                        app_path=entry["app_path"],
                        identifier=entry["identifier"],
                        display_name_initials=entry["initials"],
                        source=path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing %s: %s", path, e)
