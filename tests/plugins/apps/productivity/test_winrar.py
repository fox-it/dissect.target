from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey
from dissect.target.plugins.apps.productivity.winrar import WinRarPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_winrar_windows(target_win_users: Target, hive_hku: VirtualHive) -> None:
    """Test if we detect WinRAR dialog artifacts."""

    key_path = "Software\\WinRAR\\DialogEditHistory\\ArcName"
    key = VirtualKey(hive_hku, key_path)
    key.add_value("0", "example.rar")
    key.timestamp = datetime(2025, 12, 31, 12, 34, 0, tzinfo=timezone.utc)
    hive_hku.map_key(key_path, key)

    key_path = "Software\\WinRAR\\DialogEditHistory\\ExtrPath"
    key = VirtualKey(hive_hku, key_path)
    key.add_value("0", "C:\\Users\\Administrator\\Desktop\\example-rar")
    key.timestamp = datetime(2025, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    hive_hku.map_key(key_path, key)

    target_win_users.add_plugin(WinRarPlugin)

    results = list(target_win_users.winrar())
    assert len(results) == 2

    assert results[0]._desc.name == "application/productivity/winrar"
    assert results[0].ts == datetime(2025, 12, 31, 12, 34, 0, tzinfo=timezone.utc)
    assert results[0].path == "example.rar"

    assert results[1]._desc.name == "application/productivity/winrar"
    assert results[1].ts == datetime(2025, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    assert results[1].path == "C:\\Users\\Administrator\\Desktop\\example-rar"
