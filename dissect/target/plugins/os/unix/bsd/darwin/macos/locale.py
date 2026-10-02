from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.localeutil import normalize_language
from dissect.target.plugin import export
from dissect.target.plugins.os.default.locale import LocalePlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


class LocalePlugin(LocalePlugin):
    """macOS locale plugin.

    This plugin retrieves locale information from the system.
    """

    GLOBAL = "/Library/Preferences/.GlobalPreferences.plist"

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self) -> None:
        if not self.target.os == "macos":
            raise UnsupportedPluginError("Unsupported Plugin")

    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    @export(property=True)
    def timezone(self) -> str | None:
        """Return the configured timezone of the system.

        .. code-block::

                ["Europe", "Amsterdam"] -> Europe/Amsterdam
                ["UTC"]                 -> UTC
        """
        preferences = plistlib.load(self.target.fs.path(self.GLOBAL).open())
        tz_data = preferences.get("com.apple.TimeZonePref.Last_Selected_City")

        tz_candidate = "/".join(tz_data)
        result = self.check_timezone(tz_candidate)
        if result:
            return result

        for entry in tz_data:
            result = self.check_timezone(entry)
            if result:
                return result

        return None

    def check_timezone(self, entry: str) -> str | None:
        try:
            return ZoneInfo(entry).key
        except (ZoneInfoNotFoundError, PermissionError):
            return None

    @export(property=True)
    def language(self) -> str | None:
        """Return a list of installed languages on the system."""
        preferences = plistlib.load(self.target.fs.path(self.GLOBAL).open())
        languages = preferences["AppleLanguages"]
        clean_languages = []
        for lang in languages:
            language = normalize_language(lang.replace("-", "_"))
            if language not in clean_languages:
                clean_languages.append(language)

        return clean_languages

    @export(property=True)
    def install_date(self) -> str | None:
        """Return the installation date of the system."""
        mtime = self.target.fs.path("/private/var/db/.AppleSetupDone").lstat().st_mtime
        return datetime.fromtimestamp(mtime, timezone.utc)

    @export(property=True)
    def location_services_active(self) -> bool | None:
        """Return whether location services are active."""
        path = self.target.fs.path("/Library/Preferences/com.apple.timezone.auto.plist")

        if not path.exists():
            return None

        try:
            with path.open("rb") as fh:
                plist = plistlib.load(fh)
            return plist.get("Active")
        except Exception:
            return None
