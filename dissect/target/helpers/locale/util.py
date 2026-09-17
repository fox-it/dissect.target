from __future__ import annotations

from locale import normalize

from dissect.target.helpers.locale.windows_zones import WINDOWS_ZONE_MAP


def normalize_timezone(input: str) -> str:
    """Return normalized timezone format per IANA TZ standard.

    Takes a Windows registry ``TimeZoneKeyName`` string as input and translates it to IANA TZ format.
    Will return the IANA preferred territory ``001`` value of the corresponding timezone.

    For example, ``Pacific Standard Time`` is translated to ``America/Los_Angeles``.

    Returns the original input string if the input does not exist in the CLDR ``WindowsZones.xml`` document.
    """
    return WINDOWS_ZONE_MAP.get(input, input)


def normalize_language(input: str) -> str:
    """Returns normalized locales per ISO-3166. Takes Unix LANG locales and Windows registry languages as input.

    Output will be in the format ``ISO-3166-1-alpha-2-code_ISO-3166-2``, e.g.: ``en_US``, ``nl_NL`` or ``en_GB``.

    References:
        - https://en.wikipedia.org/wiki/ISO_3166
        - https://en.wikipedia.org/wiki/ISO_3166-1
        - https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
        - https://en.wikipedia.org/wiki/ISO_3166-2
    """
    return normalize(input.replace("-", "_", 1)).split(".")[0]
