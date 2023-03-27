import logging
import re
import urllib.parse
from datetime import datetime, timezone, tzinfo
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Iterator, Union

from dissect.util.ts import from_unix

from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


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


STRIP_RE = re.compile(r"^[\s\x00]*|[\s\x00]*$")


def year_rollover_helper(
    path: Path, re_ts: Union[str, re.Pattern], ts_format: str, tzinfo: tzinfo = timezone.utc
) -> Iterator[tuple[datetime, str]]:
    """Helper function for determining the correct timestamps for log files without year notation.

    Supports compressed files by using :func:`open_decompress`.

    Args:
        path: A path to the log file to parse.
        re_ts: Regex pattern for extracting the timestamp from each line.
        ts_format: Time format specification for parsing the timestamp.
        tzinfo: The timezone to use when parsing timestamps.

    Returns:
        An iterator of tuples of the parsed timestamp and the lines of the file in reverse.
    """
    # Convert the mtime to the local timezone so that we get the correct year
    mtime = path.stat().st_mtime
    current_year = from_unix(mtime).astimezone(tzinfo).year
    last_seen_month = None

    with fsutil.open_decompress(path, "rt") as fh:
        warned = False
        for line in fsutil.reverse_readlines(fh):
            line = STRIP_RE.sub(r"", line)
            if not line:
                continue

            timestamp = re.search(re_ts, line)

            if not timestamp:
                if not warned:
                    log.warning("No timestamp found in one of the lines in %s!", path)
                    warned = True
                log.debug("Skipping line: %s", line)
                continue

            relative_ts = datetime.strptime(timestamp.group(0), ts_format)
            if last_seen_month and relative_ts.month > last_seen_month:
                current_year -= 1
            last_seen_month = relative_ts.month

            yield relative_ts.replace(year=current_year, tzinfo=tzinfo), line
