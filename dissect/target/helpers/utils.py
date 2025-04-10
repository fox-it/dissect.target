from __future__ import annotations

import logging
import re
import urllib.parse
from datetime import datetime, timezone, tzinfo
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO, TypeVar

from dissect.util.ts import from_unix

from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

log = logging.getLogger(__name__)


def findall(buf: bytes, needle: bytes) -> Iterator[int]:
    offset = 0
    while True:
        offset = buf.find(needle, offset)
        if offset == -1:
            break

        yield offset
        offset += 1


T = TypeVar("T")


def to_list(value: T | list[T] | None) -> list[T]:
    """Convert a single value or a list of values to a list. A value of ``None`` is converted to an empty list.

    Args:
        value: The value to convert.

    Returns:
        A list of values.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        return [value]

    return value


class StrEnum(str, Enum):
    """Sortable and serializible string-based enum."""


def parse_path_uri(path: Path) -> tuple[str | None, str | None, str | None]:
    if path is None:
        return None, None, None
    parsed_path = urllib.parse.urlparse(str(path))
    parsed_query = urllib.parse.parse_qs(parsed_path.query, keep_blank_values=True)
    return parsed_path.scheme, parsed_path.path, parsed_query


def parse_options_string(options: str) -> dict[str, str | bool]:
    result = {}
    for opt in options.split(","):
        if "=" in opt:
            key, _, value = opt.partition("=")
            result[key] = value
        else:
            result[opt] = True
    return result


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
    path: Path, re_ts: str | re.Pattern, ts_format: str, tzinfo: tzinfo = timezone.utc
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

            # We have to append the current_year to strptime instead of adding it using replace later.
            # This prevents DeprecationWarnings on cpython >= 3.13 and Exceptions on cpython >= 3.15.
            # See https://github.com/python/cpython/issues/70647 and https://github.com/python/cpython/pull/117107.
            # Use 1904 instead of 1900 to include leap days (29 Feb).
            try:
                compare_ts = datetime.strptime(f"{timestamp.group(0)};1904", f"{ts_format};%Y").replace(tzinfo=tzinfo)
            except ValueError as e:
                log.warning("Unable to create comparison timestamp for %r in line %r: %s", timestamp.group(0), line, e)
                log.debug("", exc_info=e)
                continue

            if last_seen_month and compare_ts.month > last_seen_month:
                current_year -= 1
            last_seen_month = compare_ts.month

            try:
                relative_ts = datetime.strptime(f"{timestamp.group(0)};{current_year}", f"{ts_format};%Y").replace(
                    tzinfo=tzinfo
                )
            except ValueError as e:
                log.warning(
                    "Timestamp '%s;%s' does not match format '%s;%%Y', skipping line %r: %s",
                    timestamp.group(0),
                    current_year,
                    ts_format,
                    line,
                    e,
                )
                log.debug("", exc_info=e)
                continue

            yield relative_ts, line
