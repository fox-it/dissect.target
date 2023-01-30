import defusedxml.ElementTree as ET
from locale import normalize


windows_zones = {
    child.attrib["other"]: child.attrib["type"]
    for child in ET.parse("./dissect/target/helpers/data/windowsZones.xml").findall(
        "./windowsZones/mapTimezones/mapZone"
    )
    if child.attrib["territory"] == "001"
}


def normalize_timezone(input: str) -> str:
    """Returns normalized timezone format per IANA TZ standard.

    Takes a Windows registry TimeZoneKeyName string as input, eg.
    ``Pacific Standard Time`` and translates it to IANA TZ format ``America/Los_Angeles``.
    Will return the IANA peferred territory 001 value of the corresponding timezone.
    """

    if input in windows_zones:
        return windows_zones[input]
    else:
        return input


def normalize_language(input: str) -> str:
    """Returns normalized locales per ISO-3166. Takes unix LANG locales and Windows registry languages as input.

    Output will be in the format ``ISO-3166-1_ISO-3166-2`` eg. ``en_US``, ``nl_NL`` or ``en_GB``.

    Uses Python's ``locale.normalize()`` function.
    """

    return normalize(input).split(".")[0]
