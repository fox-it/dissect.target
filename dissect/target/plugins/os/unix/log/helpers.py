import itertools
import logging
import re
from datetime import datetime
from typing import Iterator

from dissect.target.helpers.fsutil import TargetPath, open_decompress

log = logging.getLogger(__name__)

_RE_TS = r"^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}"
_RE_TS_ISO = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2}"

RE_TS = re.compile(_RE_TS)
RE_TS_ISO = re.compile(_RE_TS_ISO)
RE_LINE = re.compile(
    rf"(?P<ts>{_RE_TS}|{_RE_TS_ISO})\s(?P<hostname>\S+)\s(?P<service>\S+?)(\[(?P<pid>\d+)\])?:\s(?P<message>.+)$"
)


def iso_readlines(file: TargetPath) -> Iterator[tuple[datetime, str]]:
    """Iterator reading the provided log file in ISO format. Mimics ``year_rollover_helper`` behaviour."""

    with open_decompress(file, "rt") as fh:
        for line in fh:
            if not (match := RE_TS_ISO.match(line)):
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


def is_iso_fmt(file: TargetPath) -> bool:
    """Determine if the provided log file uses ISO 8601 timestamp format logging or not."""
    return any(itertools.islice(iso_readlines(file), 0, 2))
