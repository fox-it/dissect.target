from dissect.util.ts import from_unix

from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.generic import GenericPlugin


def test_windows_generic_install_date(target_win_users, fs_win, hive_hklm):
    currentversion_key_name = "Software\\Microsoft\\Windows NT\\CurrentVersion"
    currentversion_key = VirtualKey(hive_hklm, currentversion_key_name)
    currentversion_key.add_value("InstallDate", VirtualValue(hive_hklm, "InstallDate", 0))
    hive_hklm.map_key(currentversion_key_name, currentversion_key)
    target_win_users.add_plugin(GenericPlugin)

    assert target_win_users.install_date == from_unix(0)
