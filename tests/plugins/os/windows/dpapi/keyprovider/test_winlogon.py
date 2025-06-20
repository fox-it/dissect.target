from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualKey
from dissect.target.plugins.os.windows.dpapi.keyprovider.winlogon import WinlogonDefaultPasswordKeyProviderPlugin

if TYPE_CHECKING:
    from dissect.target.helpers.regutil import VirtualHive
    from dissect.target.target import Target


def test_dpapi_keyprovider_winlogon(target_win: Target, hive_hklm: VirtualHive) -> None:
    """test if we find a Winlogon DefaultPassword entry in the registry."""

    winlogon_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    winlogon_key = VirtualKey(hive_hklm, winlogon_path)
    winlogon_key.add_value("DefaultPassword", "password")
    hive_hklm.map_key(winlogon_path, winlogon_key)

    target_win.add_plugin(WinlogonDefaultPasswordKeyProviderPlugin)

    key = next(target_win._dpapi_keyprovider_winlogon_defaultpassword())

    assert key == ("_dpapi_keyprovider_winlogon_defaultpassword", "password")
