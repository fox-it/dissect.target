import re
import urllib.parse
from enum import Enum
from typing import BinaryIO


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


def readinto(buffer: bytearray, fh: BinaryIO) -> int:
    """A readinto implementation that uses ``read()``.

    Reads the length of the buffer from ``fh``, and fills the buffer with said data.

    Args:
        buffer: The buffer we read the data into.
        fh: The file-like object we use for reading.

    Returns:
        the size in bytes that was read.
    """
    data = fh.read(len(buffer))
    size = len(data)
    buffer[:size] = data
    return size
