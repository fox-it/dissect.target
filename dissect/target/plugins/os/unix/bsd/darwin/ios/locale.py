from __future__ import annotations

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.localeutil import normalize_language
from dissect.target.plugin import OperatingSystem, Plugin, export
from dissect.target.plugins.os.unix.locale import timezone_from_path


class LocalePlugin(Plugin):
    """Locale plugin for iOS targets."""

    def check_compatible(self) -> None:
        if not self.target.os == OperatingSystem.IOS:
            raise UnsupportedPluginError

    @export(property=True)
    def timezone(self) -> str | None:
        """Return the configured localtime of the iOS system."""
        if (localtime := self.target.fs.path("/private/var/db/timezone/localtime")).exists():
            return timezone_from_path(localtime.read_text().strip())
        return None

    @export(property=True)
    def language(self) -> list[str]:
        """Return the configured language(s) of the iOS system."""
        return list(map(normalize_language, self.target._os._config.GLOBAL["AppleLanguages"]))
