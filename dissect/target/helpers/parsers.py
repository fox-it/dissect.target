from __future__ import annotations

import datetime
from typing import Callable

# Define a type hint for our parser function for better readability and type checking.
# It's a function that takes a string and returns a datetime object or None.
DateTimeParser = Callable[[str], datetime.datetime | None]


def default_datetime_parser(date_string: str) -> datetime.datetime | None:
    """Parses a date string by trying a list of common formats.

    This is the default implementation that can be swapped out.

    Args:
        date_string: The string representation of the date.

    Returns:
        A datetime object with UTC timezone, or None if parsing fails.
    """
    if not isinstance(date_string, str):
        return None

    date_formats = [
        "%Y%m%d",  # e.g., 20231225
        "%m/%d/%Y",  # e.g., 12/25/2023
        "%d/%m/%Y",  # e.g., 25/12/2023
        "%d.%m.%Y",  # e.g., 25.12.2023
    ]
    for fmt in date_formats:
        try:
            return datetime.datetime.strptime(date_string, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:  # noqa: PERF203
            continue

    return None
