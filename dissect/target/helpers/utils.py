import re
import urllib.parse
from pathlib import Path
from enum import Enum
from typing import BinaryIO, Union
from dissect.target.loader import Loader, LOADERS_BY_SCHEME


class StrEnum(str, Enum):
    """Sortable and serializible string-based enum"""


def list_to_frozen_set(function):
    def wrapper(*args):
        args = [frozenset(x) if type(x) == list else x for x in args]
        return function(*args)

    return wrapper


def parse_path_uri(path: Union[str, Path]) -> tuple[Optional[Path], Optional[Loader], dict, str]:
    """Converts a path string into a path while taking URIs into account.

    If the path string contains an URI the scheme will be used to infer
    the loader by using the LOADERS_BY_SCHEME dict. In case of an URI
    the path will be set to the remainder of the string (including
    host and port) to form a pseudo path that can easily be used by
    URI-based loaders.

    If no loader can be inferred, the loader will be set to None
    and the default detection mechanisms of the caller should proceed,
    this should also apply to the 'file://' and 'raw://' schemes.

    Additionally to remain backward compatible with the previous version
    of this function, the scheme string and query parameters will be returned.
    The scheme string will be returned even if the loader has not been
    inferred.

    Args:
        path: string describing the path of a target or Path.

    Returns:
        - a Path object (wrapped around the provided path string)
        - the inferred loader or None
        - query parameters (always a dict)
        - scheme string if any (or an empty string)
    """

    if path is None:
        return None, None, {}, ""

    # In case we have a path object
    path = str(path)
    inferred_loader = None
    # urlparse isn't good enough, parses C:\ as scheme C!
    # also urlparse path == '' which is useless for practical use as pseudo path
    scheme = path.split("://")[0] if path.find("://") > -1 else ""
    # we *can* use urllib to extract the query string though
    parsed_path = urllib.parse.urlparse(path)
    parsed_query = urllib.parse.parse_qs(parsed_path.query, keep_blank_values=True)
    if scheme != "":
        inferred_loader = LOADERS_BY_SCHEME.get(scheme)
        # because we want to keep the 'pseudo path' we have to do this part ourselves
        path = path[len(scheme) + 3 :].split("?")[0]
    return Path(path), inferred_loader, parsed_query, scheme


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
