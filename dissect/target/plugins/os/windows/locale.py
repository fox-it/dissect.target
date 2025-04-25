from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.localeutil import normalize_language, normalize_timezone
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.default.locale import LocalePlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

WindowsKeyboardRecord = TargetRecordDescriptor(
    "windows/keyboard",
    [
        ("string", "layout"),
        ("string", "id"),
    ],
)


class WindowsLocalePlugin(LocalePlugin):
    """Windows locale plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.LANG_DICT = {
            lang.name: lang.value
            for k in self.target.registry.key("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\\DosKeybCodes")
            for lang in k.values()
        }

    def check_compatible(self) -> None:
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("Unsupported Plugin")

    @export(property=True)
    def timezone(self) -> str | None:
        """Get the configured timezone of the system in IANA TZ standard format."""
        return normalize_timezone(self.target.datetime.tzinfo.name)

    @export(property=True)
    def language(self) -> str | None:
        """Get a list of installed languages on the system."""
        # HKCU\\Control Panel\\International\\User Profile" Languages
        found_languages = []
        for up in self.target.registry.keys("HKCU\\Control Panel\\International\\User Profile"):
            for subkey in up.subkeys():
                language = normalize_language(subkey.name.replace("-", "_"))
                if language not in found_languages:
                    found_languages.append(language)
        return found_languages

    @export(record=WindowsKeyboardRecord)
    def keyboard(self) -> Iterator[WindowsKeyboardRecord]:
        """Yield records of installed keyboards on the system."""
        found_keyboards = []
        for key in self.target.registry.keys("HKCU\\Keyboard Layout\\Preload"):
            for language in key.values():
                language_id = language.value
                if language_id not in found_keyboards:
                    found_keyboards.append(language_id)
                    yield WindowsKeyboardRecord(
                        layout=self.LANG_DICT.get(language_id, language_id),
                        id=language_id,
                        _target=self.target,
                    )
