import pathlib
import tempfile
import textwrap
from io import BytesIO

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.general import default
from dissect.target.plugins.os.windows import registry
from dissect.target.target import Target


def make_dummy_target():
    target = Target()
    target.add_plugin(default.DefaultPlugin)
    return target


def make_mock_target():
    with tempfile.NamedTemporaryFile(prefix="MockTarget-") as tmp_file:
        target = make_dummy_target()
        target.path = pathlib.Path(tmp_file.name)
        yield target


@pytest.fixture
def mock_target():
    yield from make_mock_target()


@pytest.fixture
def make_mock_targets(request):
    def _make_targets(size):
        for _ in range(size):
            yield from make_mock_target()

    return _make_targets


@pytest.fixture
def fs_win(tmp_path):
    fs = VirtualFilesystem(case_sensitive=False, alt_separator="\\")
    fs.map_dir("windows/system32", tmp_path)
    fs.map_dir("windows/system32/config/", tmp_path)
    yield fs


@pytest.fixture
def fs_unix():
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc")
    yield fs


@pytest.fixture
def hive_hklm():
    hive = VirtualHive()

    # set current control set to ControlSet001 and mock it
    controlset_key = "SYSTEM\\ControlSet001"
    hive.map_key(controlset_key, VirtualKey(hive, controlset_key))

    select_key = "SYSTEM\\Select"
    hive.map_key(select_key, VirtualKey(hive, select_key))
    hive.map_value(select_key, "Current", VirtualValue(hive, "Current", 1))

    yield hive


@pytest.fixture
def hive_hku():
    hive = VirtualHive()

    yield hive


@pytest.fixture
def target_win(hive_hklm, fs_win):
    mock_target = next(make_mock_target())

    mock_target.add_plugin(registry.RegistryPlugin, check_compatible=False)
    mock_target.registry.map_hive("HKEY_LOCAL_MACHINE", hive_hklm)

    mock_target.filesystems.add(fs_win)
    mock_target.apply()

    yield mock_target


@pytest.fixture
def target_unix(fs_unix):
    mock_target = next(make_mock_target())

    mock_target.filesystems.add(fs_unix)
    mock_target.fs.mount("/", fs_unix)
    mock_target.apply()
    yield mock_target


@pytest.fixture
def target_win_users(hive_hklm, hive_hku, target_win):
    key_name = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"

    profile_list_key = VirtualKey(hive_hklm, key_name)

    profile1_key = VirtualKey(hive_hklm, "S-1-5-18")
    profile1_key.add_value(
        "ProfileImagePath", VirtualValue(hive_hklm, "ProfileImagePath", "%systemroot%\\system32\\config\\systemprofile")
    )

    profile2_key = VirtualKey(hive_hklm, "S-1-5-21-3263113198-3007035898-945866154-1002")
    profile2_key.add_value("ProfileImagePath", VirtualValue(hive_hklm, "ProfileImagePath", "C:\\Users\\John"))

    profile_list_key.add_subkey("subkey1", profile1_key)
    profile_list_key.add_subkey("subkey2", profile2_key)

    hive_hklm.map_key(key_name, profile_list_key)

    target_win.registry.map_hive("HKEY_USERS\\S-1-5-21-3263113198-3007035898-945866154-1002", hive_hku)

    yield target_win


@pytest.fixture
def target_win_tzinfo(hive_hklm, target_win):
    tz_info_path = "SYSTEM\\ControlSet001\\Control\\TimeZoneInformation"
    tz_info = VirtualKey(hive_hklm, tz_info_path)
    tz_info.add_value("TimeZoneKeyName", "Easter Island Standard Time")

    eu_tz_data_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\W. Europe Standard Time"
    eu_tz_data = VirtualKey(hive_hklm, eu_tz_data_path)
    eu_tz_data.add_value("Display", "(UTC+01:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna")
    eu_tz_data.add_value("Dlt", "W. Europe Daylight Time")
    eu_tz_data.add_value("Std", "W. Europe Standard Time")
    eu_tzi = bytes.fromhex("c4ffffff00000000c4ffffff00000a0000000500030000000000000000000300000005000200000000000000")
    eu_tz_data.add_value("TZI", eu_tzi)

    east_tz_data_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\Easter Island Standard Time"
    east_tz_data = VirtualKey(hive_hklm, east_tz_data_path)
    east_tz_data.add_value("Display", "(UTC-06:00) Easter Island")
    east_tz_data.add_value("Dlt", "Easter Island Daylight Time")
    east_tz_data.add_value("Std", "Easter Island Standard Time")
    east_tzi = bytes.fromhex("6801000000000000c4ffffff0000040006000100160000000000000000000900060001001600000000000000")
    east_tz_data.add_value("TZI", east_tzi)

    dynamic_dst = VirtualKey(hive_hklm, east_tz_data_path + "\\Dynamic DST")
    dynamic_dst.add_value("FirstEntry", 2019)
    dynamic_dst.add_value("LastEntry", 2019)
    tzi_2019 = bytes.fromhex("6801000000000000c4ffffff0000040006000100160000000000000000000900060001001600000000000000")
    dynamic_dst.add_value("2019", tzi_2019)
    east_tz_data.add_subkey("Dynamic DST", dynamic_dst)

    hive_hklm.map_key(tz_info_path, tz_info)
    hive_hklm.map_key(eu_tz_data_path, eu_tz_data)
    hive_hklm.map_key(east_tz_data_path, east_tz_data)

    yield target_win


@pytest.fixture
def target_unix_users(target_unix, fs_unix):
    passwd = """
    root:x:0:0:root:/root:/bin/bash
    user:x:1000:1000:user:/home/user:/bin/bash
    """
    fs_unix.map_file_fh("/etc/passwd", BytesIO(textwrap.dedent(passwd).encode()))
    yield target_unix
