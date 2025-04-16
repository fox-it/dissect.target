from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import TYPE_CHECKING

from dissect.target.helpers.fsutil import open_decompress

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

log = logging.getLogger(__name__)

RE_TS = re.compile(r"^[A-Za-z]{3}\s*\d{1,2}\s\d{1,2}:\d{2}:\d{2}")
RE_TS_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2}")
RE_LINE = re.compile(
    r"""
    \d{2}:\d{2}\s                           # First match on the similar ending of the different timestamps
    ((?:\S+)\s)?                            # The hostname (optional), but do not capture it
    (?P<service>\S+?)(\[(?P<pid>\d+?)\])?:  # The service / daemon with optionally the PID between brackets
    (\s*(?P<message>.+?)\s*)?$              # The log message stripped from spaces left and right
    """,
    re.VERBOSE,
)


def iso_readlines(file: Path, max_lines: int | None = None) -> Iterator[tuple[datetime, str]]:
    """Iterator reading the provided log file in ISO format. Mimics ``year_rollover_helper`` behaviour."""
    with open_decompress(file, "rt") as fh:
        for i, line in enumerate(fh):
            if max_lines is not None and i >= max_lines:
                log.debug("Stopping iso_readlines enumeration in %s: max_lines=%s was reached", file, max_lines)
                break

            if not (match := RE_TS_ISO.match(line)):
                if not max_lines:
                    log.warning("No timestamp found in one of the lines in %s!", file)
                log.debug("Skipping line: %s", line)
                continue

            try:
                ts = datetime.strptime(match[0], "%Y-%m-%dT%H:%M:%S.%f%z")
            except ValueError as e:
                log.warning("Unable to parse ISO timestamp in line: %s", line)
                log.debug("", exc_info=e)
                continue

            yield ts, line


def is_iso_fmt(file: Path) -> bool:
    """Determine if the provided log file uses ISO 8601 timestamp format logging or not."""
    # We do not want to iterate of the entire file so we limit iso_readlines to the first few lines.
    # We can not use islice here since that would only work if the file is ISO formatted and thus yields results.
    return any(iso_readlines(file, max_lines=3))
