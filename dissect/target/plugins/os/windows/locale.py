from dissect.target.helpers.record import WindowsKeyboardRecord
from dissect.target.plugin import Plugin, export, internal


class LocalePlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)
        self.LANG_DICT = self._lang_dict()

    def check_compatible(self):
        pass

    @internal
    def _lang_dict(self):
        key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout\\DosKeybCodes"
        langs = {}
        for k in self.target.registry.key(key):
            for lang in k.values():
                langs[lang.name] = lang.value
        return langs

    @export(record=WindowsKeyboardRecord)
    def keyboard(self):
        """
        Yield records of installed keyboards on the system.
        """
        found_keyboards = []
        for key in self.target.registry.keys("HKCU\\Keyboard Layout\\Preload"):
            langs = key.values()
            for i in langs:
                language_id = i.value
                if language_id not in found_keyboards:
                    found_keyboards.append(language_id)
                    if language_id in self.LANG_DICT:
                        layout = self.LANG_DICT[language_id] or language_id
                    else:
                        layout = language_id
                    yield WindowsKeyboardRecord(
                        layout=layout,
                        id=language_id,
                        _target=self.target,
                    )

    @export(property=True)
    def language(self):
        """
        Get a list of installed languages on the system.
        """
        # HKCU\\Control Panel\\International\\User Profile" Languages
        found_languages = []
        ups = self.target.registry.keys("HKCU\\Control Panel\\International\\User Profile")
        for up in ups:
            for subkey in up.subkeys():
                language = subkey.name
                if language not in found_languages:
                    found_languages.append(language)
        return found_languages

    @export(property=True)
    def timezone(self):
        """
        Get the configured timezone of the system.
        """
        tzi = self.target.registry.key("HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation")
        return tzi.value("TimeZoneKeyName").value
