from __future__ import annotations

import json

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.localeutil import normalize_language
from dissect.target.plugin import export
from dissect.target.plugins.os.default.locale import LocalePlugin


class CitrixLocalePlugin(LocalePlugin):
    """Citrix Netscaler locale plugin."""

    def check_compatible(self) -> None:
        if self.target.os != "citrix-netscaler":
            raise UnsupportedPluginError("Citrix Netscaler specific plugin loaded on non-Citrix target")

    @export(property=True)
    def language(self) -> list[str] | None:
        """Return configured UI language(s)"""

        found_languages = set()

        # Iterate logon theme languages
        for file in self.target.fs.path("/var/netscaler/logon/themes/").glob("*/*.json"):
            try:
                theme = json.loads(file.read_text())
                if locale := theme.get("locale"):
                    found_languages.add(normalize_language(locale))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:  # noqa: PERF203
                self.target.log.warning("Unable to parse %s: %s", file, e)
                self.target.log.debug("", exc_info=e)

        # Find using regular BSD locations
        found_languages.update(super().language)

        return list(found_languages)
