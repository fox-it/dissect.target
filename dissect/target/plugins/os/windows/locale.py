from dissect.target.exceptions import (
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
)
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

WindowsKeyboardRecord = TargetRecordDescriptor(
    "windows/keyboard",
    [
        ("string", "layout"),
        ("string", "id"),
    ],
)


class LocalePlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)
        self.LANG_DICT = {
            lang.name: lang.value
            for k in self.target.registry.key("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\\DosKeybCodes")
            for lang in k.values()
        }

    def check_compatible(self):
        try:
            self.target.registry.key("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\\DosKeybCodes")
            self.target.registry.key("HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation")
            assert len(self.target.registry.key("HKCU\\Keyboard Layout\\Preload").keys) > 0
            assert len(self.target.registry.key("HKCU\\Control Panel\\International\\User Profile").keys) > 0
        except (RegistryKeyNotFoundError, RegistryValueNotFoundError, AssertionError):
            return False

    @export(record=WindowsKeyboardRecord)
    def keyboard(self):
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

    @export(property=True)
    def language(self):
        """Get a list of installed languages on the system."""
        # HKCU\\Control Panel\\International\\User Profile" Languages
        found_languages = []
        for up in self.target.registry.keys("HKCU\\Control Panel\\International\\User Profile"):
            for subkey in up.subkeys():
                language = subkey.name
                if language not in found_languages:
                    found_languages.append(language)
        return found_languages

    @export(property=True)
    def timezone(self):
        """Get the configured timezone of the system."""
        tzi = self.target.registry.key("HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation")
        return tzi.value("TimeZoneKeyName").value
