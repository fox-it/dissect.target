from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.regutil import RegistryHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.datetime import WindowsDateTimePlugin, c_tz, parse_systemtime_transition
from dissect.target.plugins.os.windows.locale import WindowsLocalePlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_windows_datetime(target_win_tzinfo: Target) -> None:
    target_win_tzinfo.add_plugin(WindowsDateTimePlugin)

    # Easter Island has a flipped DST to Amsterdam
    assert target_win_tzinfo.datetime.tzinfo.display == "(UTC-06:00) Easter Island"
    assert target_win_tzinfo.datetime.tzinfo.dlt_name == "Easter Island Daylight Time"
    assert target_win_tzinfo.datetime.tzinfo.std_name == "Easter Island Standard Time"
    assert 2019 in target_win_tzinfo.datetime.tzinfo.dynamic_dst

    naive_dt_may = datetime.datetime(2019, 5, 4, 12, 0, 0)  # noqa: DTZ001
    naive_dt_march = datetime.datetime(2019, 3, 4, 12, 0, 0)  # noqa: DTZ001

    local_east_st_dt = target_win_tzinfo.datetime.local(naive_dt_may)
    local_east_dt_dt = target_win_tzinfo.datetime.local(naive_dt_march)

    assert local_east_st_dt.tzinfo == target_win_tzinfo.datetime.tzinfo
    assert local_east_dt_dt.tzinfo == target_win_tzinfo.datetime.tzinfo
    assert str(local_east_st_dt) == "2019-05-04 12:00:00-06:00"
    assert str(local_east_dt_dt) == "2019-03-04 12:00:00-05:00"
    assert target_win_tzinfo.datetime.tzinfo.tzname(local_east_st_dt) == "Easter Island Standard Time"
    assert target_win_tzinfo.datetime.tzinfo.tzname(local_east_dt_dt) == "Easter Island Daylight Time"

    utc_east_st_dt = target_win_tzinfo.datetime.to_utc(local_east_st_dt)
    utc_east_dt_dt = target_win_tzinfo.datetime.to_utc(local_east_dt_dt)
    assert utc_east_st_dt == target_win_tzinfo.datetime.to_utc(naive_dt_may)
    assert utc_east_dt_dt == target_win_tzinfo.datetime.to_utc(naive_dt_march)
    assert utc_east_st_dt.tzinfo == datetime.timezone.utc
    assert utc_east_dt_dt.tzinfo == datetime.timezone.utc
    assert str(utc_east_st_dt) == "2019-05-04 18:00:00+00:00"
    assert str(utc_east_dt_dt) == "2019-03-04 17:00:00+00:00"

    eu_tzinfo = target_win_tzinfo.datetime.tz("W. Europe Standard Time")
    local_eu_st_dt = naive_dt_march.replace(tzinfo=eu_tzinfo)
    local_eu_dt_dt = naive_dt_may.replace(tzinfo=eu_tzinfo)
    assert str(local_eu_st_dt) == "2019-03-04 12:00:00+01:00"
    assert str(local_eu_dt_dt) == "2019-05-04 12:00:00+02:00"
    assert eu_tzinfo.tzname(local_eu_st_dt) == "W. Europe Standard Time"
    assert eu_tzinfo.tzname(local_eu_dt_dt) == "W. Europe Daylight Time"

    utc_eu_st_dt = local_eu_st_dt.astimezone(datetime.timezone.utc)
    utc_eu_dt_dt = local_eu_dt_dt.astimezone(datetime.timezone.utc)
    assert str(utc_eu_st_dt) == "2019-03-04 11:00:00+00:00"
    assert str(utc_eu_dt_dt) == "2019-05-04 10:00:00+00:00"

    # Test the switch moment to DST
    assert not eu_tzinfo.is_dst(datetime.datetime(2022, 3, 27, 2, 0, 0, tzinfo=eu_tzinfo))
    assert eu_tzinfo.is_dst(datetime.datetime(2022, 3, 27, 3, 0, 0, tzinfo=eu_tzinfo))

    # Test utc tzinfo is_dst
    utc_tzinfo = target_win_tzinfo.datetime.tz("UTC")
    assert not utc_tzinfo.is_dst(datetime.datetime(2022, 3, 27, 2, 0, 0, tzinfo=utc_tzinfo))


def test_windows_timezone_legacy(target_win_tzinfo_legacy: Target) -> None:
    # Older Windows version (prior to Windows 7) use localized time zone ids like "Paaseiland"
    target_win_tzinfo_legacy.add_plugin(WindowsDateTimePlugin)
    assert target_win_tzinfo_legacy.datetime.tzinfo.display == "(UTC-06:00) Easter Island"


def test_windows_datetime_foreign(target_win_users: Target, hive_hku: RegistryHive, hive_hklm: RegistryHive) -> None:
    # add keyboards
    preload_key_name = "Keyboard Layout\\Preload"
    preload_key = VirtualKey(hive_hku, preload_key_name)
    preload_key.add_value("1", VirtualValue(hive_hku, "1", "00000413"))
    preload_key.add_value("2", VirtualValue(hive_hku, "2", "00000409"))
    hive_hku.map_key(preload_key_name, preload_key)

    # add keyboard languages
    doskeybcodes_key_name = "SYSTEM\\ControlSet001\\Control\\Keyboard Layout\\DosKeybCodes"
    doskeybcodes_key = VirtualKey(hive_hklm, doskeybcodes_key_name)
    doskeybcodes_key.add_value("00000413", VirtualValue(hive_hklm, "00000413", "nl"))
    doskeybcodes_key.add_value("00000409", VirtualValue(hive_hklm, "00000409", "us"))
    hive_hklm.map_key(doskeybcodes_key_name, doskeybcodes_key)

    # add PST timezone
    tz_data_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\Pacific Standard Time"
    tz_data = VirtualKey(hive_hklm, tz_data_path)

    tz_data.add_value("Display", "(UTC-08:00) Some Localized Translation")
    tz_data.add_value("Dlt", "Some Localized Translation DLT")
    tz_data.add_value("Std", "Some Localized Translation STD")

    tz_data.add_value("MUI_Display", "@tzres.dll,-210")
    tz_data.add_value("MUI_Dlt", "@tzres.dll,-211")
    tz_data.add_value("MUI_Std", "@tzres.dll,-212")

    tzi = bytes.fromhex("e001000000000000c4ffffff00000b0000000100020000000000000000000300000002000200000000000000")
    tz_data.add_value("TZI", tzi)
    hive_hklm.map_key(tz_data_path, tz_data)

    # set configured language
    userprofile_key_name = "Control Panel\\International\\User Profile"
    userprofile_key = VirtualKey(hive_hku, userprofile_key_name)
    subkey = VirtualKey(hive_hku, "en-US")
    subkey.add_value("CachedLanguageName", "@Winlangdb.dll,-1337")
    userprofile_key.add_subkey("en-US", subkey)
    hive_hku.map_key(userprofile_key_name, userprofile_key)

    # set configured timezone
    timezoneinformation_key_name = "SYSTEM\\ControlSet001\\Control\\TimeZoneInformation"
    timezoneinformation_key = VirtualKey(hive_hklm, timezoneinformation_key_name)
    timezoneinformation_key.add_value("TimeZoneKeyName", "Pacific Standard Time")
    hive_hklm.map_key(timezoneinformation_key_name, timezoneinformation_key)

    target_win_users.add_plugin(WindowsDateTimePlugin)
    assert target_win_users.datetime.tzinfo.display == "(UTC-08:00) Pacific Time (US & Canada)"
    assert target_win_users.datetime.tzinfo.std_name == "Pacific Standard Time"
    assert target_win_users.datetime.tzinfo.dlt_name == "Pacific Daylight Time"

    target_win_users.add_plugin(WindowsLocalePlugin)
    assert target_win_users.timezone == "America/Los_Angeles"


def test_parse_systemtime_transition() -> None:
    # Test behaviour where not all week days are defined in every week for that month
    systemtime = c_tz._SYSTEMTIME(wDay=5, wMonth=10)
    output = parse_systemtime_transition(systemtime, 2025)
    assert output == datetime.datetime(2025, 10, 26, tzinfo=None)  # noqa

    # Test behaviour where a weekday of the month occurs 5 times during that month
    systemtime = c_tz._SYSTEMTIME(wDay=5, wMonth=10, wDayOfWeek=4)
    output = parse_systemtime_transition(systemtime, 2025)
    assert output == datetime.datetime(2025, 10, 30, tzinfo=None)  # noqa

    # wDay in this case should only go between 1-5, so this should crash
    systemtime = c_tz._SYSTEMTIME(wDay=6)
    with pytest.raises(ValueError, match="systemtime.wDay should be between 1 and 5"):
        parse_systemtime_transition(systemtime, 2025)

    systemtime = c_tz._SYSTEMTIME(wDay=0)
    with pytest.raises(ValueError, match="systemtime.wDay should be between 1 and 5"):
        parse_systemtime_transition(systemtime, 2025)
