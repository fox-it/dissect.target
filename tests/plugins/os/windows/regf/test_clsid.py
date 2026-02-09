from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.clsid import CLSIDPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_clsid_plugin(target_win_users: Target, hive_hklm: VirtualHive) -> None:
    clsid_key_name = "SOFTWARE\\Classes\\CLSID"
    clsid_key = VirtualKey(hive_hklm, clsid_key_name)

    subkey_name = "{20894375-46AE-46E2-BAFD-CB38975CDCE6}"
    subkey = VirtualKey(hive_hklm, subkey_name)
    subkey.add_value("(Default)", VirtualValue(hive_hklm, "(Default)", "ShareHandler Class"))

    value_str = "C:\\Users\\John\\AppData\\Local\\Microsoft\\OneDrive\\21.230.1107.0004\\FileSyncShell64.dll"
    subsubkey_name = "InprocServer32"
    subsubkey = VirtualKey(hive_hklm, subsubkey_name)
    subsubkey.add_value("(Default)", VirtualValue(hive_hklm, "(Default)", value_str))

    subkey.add_subkey(subsubkey_name, subsubkey)
    clsid_key.add_subkey(subkey_name, subkey)
    hive_hklm.map_key(clsid_key_name, clsid_key)

    target_win_users.add_plugin(CLSIDPlugin)

    results = list(target_win_users.clsid())

    assert len(results) == 1

    result = results[0]

    assert result.regf_hive_path is None
    assert result.value == value_str
