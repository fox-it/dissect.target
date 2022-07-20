import re
import urllib.parse
from enum import Enum


class StrEnum(str, Enum):
    """Sortable and serializible string-based enum"""


def list_to_frozen_set(function):
    def wrapper(*args):
        args = [frozenset(x) if type(x) == list else x for x in args]
        return function(*args)

    return wrapper


def parse_path_uri(path):
    if path is None:
        return None, None, None
    parsed_path = urllib.parse.urlparse(str(path))
    parsed_query = urllib.parse.parse_qs(parsed_path.query, keep_blank_values=True)
    return parsed_path.scheme, parsed_path.path, parsed_query


SLUG_RE = re.compile(r"[/\\ ]")


def slugify(name: str) -> str:
    """Return name with all slashes '/', backslashes '\\' and spaces ' ' replaced by underscores '_'.

    This is useful to turn a name into something that can be used as filename.
    """
    return SLUG_RE.sub("_", name)
