from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import re


def parse_timestamp(timestamp: re.Match) -> datetime:
    """Parse a timestamp match into a datetime object.

    Attempts to parse the matched string as an ISO 8601 datetime. If that fails,
    falls back to parsing a syslog-style timestamp ("%b %d %H:%M:%S") and assigns UTC timezone.

    Args:
        timestamp (re.Match): A regex match object containing the timestamp string.

    Returns:
        datetime: The parsed datetime object.
    """
    ts = None
    value = timestamp.group()
    try:
        value = value.removesuffix("-0")

        ts = datetime.fromisoformat(value)
    except ValueError:
        ts = datetime.strptime(value, "%b %d %H:%M:%S").replace(tzinfo=timezone.utc)

    return ts
