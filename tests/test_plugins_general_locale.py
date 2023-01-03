import textwrap
from io import BytesIO

from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.unix.locale import LocalePlugin as UnixLocalePlugin
from dissect.target.plugins.os.windows.locale import LocalePlugin as WindowsLocalePlugin

from ._utils import absolute_path


def test_locale_plugin_windows(target_win_users, hive_hku, hive_hklm):
    """
    Hive structure originates from a Windows Server 2019 installation.
    """

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


def test_locale_plugin_unix(target_unix_users, fs_unix):
    """
    Locale locations originate from Ubuntu 20.
    """

    fs_unix.map_file_fh("/etc/timezone", BytesIO(textwrap.dedent("Europe/Amsterdam").encode()))
    fs_unix.map_file_fh("/etc/default/locale", BytesIO(textwrap.dedent("LANG=en_US.UTF-8").encode()))
    fs_unix.map_file("/etc/default/keyboard", absolute_path("data/unix-logs/locale/keyboard"))
    target_unix_users.add_plugin(UnixLocalePlugin)

    assert target_unix_users.timezone == "Europe/Amsterdam"
    assert target_unix_users.language == "en_US.UTF-8"
    keyboard = list(target_unix_users.keyboard())
    assert len(keyboard) == 1
    assert keyboard[0].layout == "us"
    assert keyboard[0].model == "pc105"
    assert keyboard[0].variant == ""
    assert keyboard[0].options == ""
    assert keyboard[0].backspace == "guess"
