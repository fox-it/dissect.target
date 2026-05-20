from __future__ import annotations

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.localeutil import normalize_language
from dissect.target.plugin import OperatingSystem, Plugin, export


class LocalePlugin(Plugin):
    """Locale plugin for Android targets."""

    def check_compatible(self) -> None:
        if not self.target.os == OperatingSystem.ANDROID:
            raise UnsupportedPluginError

    @export(property=True)
    def timezone(self) -> str | None:
        """Return the configured localtime of the Android system."""
        return self.target._os.props.get("persist.sys.timezone")

    @export(property=True)
    def language(self) -> list[str]:
        """Return the configured language(s) of the Android system."""
        if locale := self.target._os.props.get("persist.sys.locale"):
            return [normalize_language(locale)]
        return []
