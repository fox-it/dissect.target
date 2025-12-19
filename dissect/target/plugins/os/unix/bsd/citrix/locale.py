from __future__ import annotations

import json
import re

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.localeutil import normalize_language
from dissect.target.plugin import export
from dissect.target.plugins.os.default.locale import LocalePlugin

RE_CONFIG_TIMEZONE = re.compile(
    r'set ns param.* -timezone "GMT\+(?P<hours>[0-9]+):(?P<minutes>[0-9]+)-.*-(?P<zone_name>.+)"'
)


class CitrixLocalePlugin(LocalePlugin):
    """Citrix Netscaler locale plugin."""

    def check_compatible(self) -> None:
        if self.target.os != "citrix-netscaler":
            raise UnsupportedPluginError("Citrix Netscaler specific plugin loaded on non-Citrix target")

    @export(property=True)
    def timezone(self) -> str | None:
        """Return configured timezone."""
        # Collect timezone from nsconfig/ns.conf or from shell/date.out if exists
        for path in self.target.fs.path("/flash/nsconfig/").glob("ns.conf*"):
            if match := RE_CONFIG_TIMEZONE.search(path.read_text()):
                return match.groupdict()["zone_name"]

        # Netscaler collector specific check:
        # If timezone not set in ns.conf it is often UTC, lets check for that.
        if (path := self.target.fs.path("/shell/date.out")).exists() and "UTC" in path.read_text():
            return "UTC"

        return None

    @export(property=True)
    def language(self) -> list[str] | None:
        """Return configured UI language(s)."""

        found_languages = set()

        # Iterate logon theme languages
        for path in self.target.fs.path("/var/netscaler/logon/themes/").glob("*/*.json"):
            try:
                theme = json.loads(path.read_text())
                if locale := theme.get("locale"):
                    found_languages.add(normalize_language(locale))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:  # noqa: PERF203
                self.target.log.warning("Unable to parse %s: %s", path, e)
                self.target.log.debug("", exc_info=e)

        # Find using regular BSD locations
        found_languages.update(super().language)

        return list(found_languages)
