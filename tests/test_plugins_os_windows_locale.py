from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.locale import LocalePlugin as WindowsLocalePlugin


def test_locale_plugin_windows(target_win_users, hive_hku, hive_hklm):
    # Hive structure originates from a Windows Server 2019 installation.

    # language dict
    doskeybcodes_key_name = "SYSTEM\\ControlSet001\\Control\\Keyboard Layout\\DosKeybCodes"
    doskeybcodes_key = VirtualKey(hive_hklm, doskeybcodes_key_name)
    doskeybcodes_key.add_value("00000413", VirtualValue(hive_hku, "00000413", "nl"))
    doskeybcodes_key.add_value("00000409", VirtualValue(hive_hku, "00000409", "us"))
    hive_hklm.map_key(doskeybcodes_key_name, doskeybcodes_key)

    # installed keyboards
    preload_key_name = "Keyboard Layout\\Preload"
    preload_key = VirtualKey(hive_hku, preload_key_name)
    preload_key.add_value("1", VirtualValue(hive_hku, "1", "00000413"))
    preload_key.add_value("2", VirtualValue(hive_hku, "2", "00000409"))
    hive_hku.map_key(preload_key_name, preload_key)

    # installed languages
    userprofile_key_name = "Control Panel\\International\\User Profile"
    userprofile_key = VirtualKey(hive_hku, userprofile_key_name)
    subkey = VirtualKey(hive_hku, "en-US")
    subkey.add_value("CachedLanguageName", "@Winlangdb.dll,-1337")
    userprofile_key.add_subkey("en-US", subkey)
    hive_hku.map_key(userprofile_key_name, userprofile_key)

    # configured timezone
    timezoneinformation_key_name = "SYSTEM\\ControlSet001\\Control\\TimeZoneInformation"
    timezoneinformation_key = VirtualKey(hive_hklm, timezoneinformation_key_name)
    timezoneinformation_key.add_value("TimeZoneKeyName", "Pacific Standard Time")
    hive_hklm.map_key(timezoneinformation_key_name, timezoneinformation_key)

    target_win_users.add_plugin(WindowsLocalePlugin)
    assert target_win_users.language == ["en-US"]
    assert target_win_users.timezone == "Pacific Standard Time"

    keyboard = list(target_win_users.keyboard())
    assert len(keyboard) == 2
    assert keyboard[0].layout == "nl"
    assert keyboard[0].id == "00000413"
    assert keyboard[1].layout == "us"
    assert keyboard[1].id == "00000409"
