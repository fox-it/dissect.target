from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import re
    from pathlib import Path

    from dissect.target.plugin import Plugin
    from dissect.target.plugins.general.users import UserDetails


def _build_userdirs(plugin: Plugin, hist_paths: list[str]) -> set[tuple[UserDetails, Path]]:
    """Join the selected dirs with the user home path.

    Args:
        hist_paths: A list with paths as strings.

    Returns:
        List of tuples containing user and unique file path objects.
    """
    users_dirs: set[tuple] = set()
    for user_details in plugin.target.user_details.all_with_home():
        for d in hist_paths:
            home_dir: Path = user_details.home_path
            for cur_dir in home_dir.glob(d):
                cur_dir = cur_dir.resolve()
                if cur_dir.exists():
                    users_dirs.add((user_details, cur_dir))
    return users_dirs


def parse_timestamp(timestamp: re.Match) -> datetime:
    ts = None
    try:
        ts = datetime.fromisoformat(timestamp.group())
    except ValueError:
        ts = datetime.strptime(timestamp.group(), "%b %d %H:%M:%S").replace(tzinfo=timezone.utc)

    return ts
