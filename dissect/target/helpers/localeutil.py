import importlib
import importlib.resources
from locale import normalize
from pathlib import Path

import defusedxml.ElementTree as ET


def normalize_timezone(input: str) -> str:
    """Returns normalized timezone format per IANA TZ standard.

    Takes a Windows registry ``TimeZoneKeyName`` string as input and translates it to IANA TZ format.
    Will return the IANA preferred territory ``001`` value of the corresponding timezone.

    For example, ``Pacific Standard Time`` is translated to ``America/Los_Angeles``.
    """

    return WINDOWS_ZONE_MAP.get(input, input)


def normalize_language(input: str) -> str:
    """Returns normalized locales per ISO-3166. Takes Unix LANG locales and Windows registry languages as input.

    Output will be in the format ``ISO-3166-1_ISO-3166-2``, e.g.: ``en_US``, ``nl_NL`` or ``en_GB``.
    """

    return normalize(input).split(".")[0]


def get_resource_string(path: str) -> str:
    return _get_resource_path(path).read_text()


def _get_resource_path(path: str) -> Path:
    root = importlib.resources.files(__package__) if __package__ else Path(__file__).parent
    fpath = root.joinpath(path)

    if not fpath.exists():
        raise IOError(f"Can't find resource {fpath}")

    return fpath


WINDOWS_ZONE_MAP = {
    child.attrib["other"]: child.attrib["type"]
    for child in ET.fromstring(get_resource_string("data/windowsZones.xml")).findall(
        "./windowsZones/mapTimezones/mapZone"
    )
    if child.attrib["territory"] == "001"
}
