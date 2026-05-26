from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import re


def parse_timestamp(timestamp: re.Match) -> datetime:
    ts = None
    value = timestamp.group()
    try:
        value = value.removesuffix("-0")

        ts = datetime.fromisoformat(value)
    except ValueError:
        ts = datetime.strptime(value, "%b %d %H:%M:%S").replace(tzinfo=timezone.utc)

    return ts
