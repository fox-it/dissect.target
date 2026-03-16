from __future__ import annotations

import plistlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.localeutil import normalize_language
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.default.locale import LocalePlugin

if TYPE_CHECKING:

    from dissect.target.target import Target

WindowsKeyboardRecord = TargetRecordDescriptor(
    "windows/keyboard",
    [
        ("string", "layout"),
        ("string", "language_id"),
    ],
)


class OSXLocalePlugin(LocalePlugin):
    """Windows locale plugin."""

    GLOBAL = "/Library/Preferences/.GlobalPreferences.plist"

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self) -> None:
        if not self.target.os == "macos":
            raise UnsupportedPluginError("Unsupported Plugin")

    @export(property=True)
    def timezone(self) -> str | None:
        """Get the configured timezone of the system in IANA TZ standard format."""
        preferences = plistlib.load(self.target.fs.path(self.GLOBAL).open())
        tz_data = preferences["com.apple.TimeZonePref.Last_Selected_City"]
        tz = None

        for entry in tz_data:
            try:
                tz = ZoneInfo(entry).key
            except ZoneInfoNotFoundError:
                continue

        return tz

    @export(property=True)
    def language(self) -> str | None:
        """Get a list of installed languages on the system."""
        # HKCU\\Control Panel\\International\\User Profile" Languages

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
        mtime = self.target.fs.path("/private/var/db/.AppleSetupDone").lstat().st_mtime
        return datetime.fromtimestamp(mtime, timezone.utc)
