from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualKey
from dissect.target.plugins.os.windows.credential.winlogon import WinlogonPlugin

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import VirtualHive
    from dissect.target.target import Target


def test_windows_credential_winlogon(target_win: Target, hive_hklm: VirtualHive) -> None:
    """Test if we can find a Winlogon DefaultPassword entry in the registry."""

    winlogon_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    winlogon_key = VirtualKey(hive_hklm, winlogon_path)
    winlogon_key.timestamp = datetime(2025, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    winlogon_key.add_value("DefaultPassword", "password")
    hive_hklm.map_key(winlogon_path, winlogon_key)

    target_win.add_plugin(WinlogonPlugin)

    record = next(target_win.winlogon())

    assert record.ts_mtime == datetime(2025, 12, 31, 13, 37, 0, tzinfo=timezone.utc)
    assert record.password == "password"
