from __future__ import annotations

import pathlib
import tempfile
import textwrap
from io import BytesIO
from typing import Callable, Iterator

import pytest

from dissect.target.filesystem import Filesystem, VirtualFilesystem, VirtualSymlink
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugin import OSPlugin
from dissect.target.plugins.general import default
from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.plugins.os.unix.bsd.citrix._os import CitrixPlugin
from dissect.target.plugins.os.unix.bsd.osx._os import MacPlugin
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from dissect.target.plugins.os.unix.linux.debian._os import DebianPlugin
from dissect.target.plugins.os.unix.linux.redhat._os import RedHatPlugin
from dissect.target.plugins.os.unix.linux.suse._os import SuSEPlugin
from dissect.target.plugins.os.windows import registry
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.plugins.os.windows.dpapi.dpapi import DPAPIPlugin
from dissect.target.target import Target
from tests._utils import absolute_path

# Test if the data/ directory is present and if not, as is the case in Python
# source distributions of dissect.target, we give an error
data_dir = absolute_path("_data")
if not pathlib.Path(data_dir).is_dir():
    raise pytest.PytestConfigWarning(
        f"No test data directory {data_dir} found.\n"
        "This can happen when you have downloaded the source distribution\n"
        "of dissect.target from pypi.org. If so, retrieve the test data from\n"
        "the dissect.target GitHub repository at:\n"
        "https://github.com/fox-it/dissect.target"
    )


def make_mock_target(tmp_path: pathlib.Path) -> Iterator[Target]:
    with tempfile.NamedTemporaryFile(dir=tmp_path, prefix="MockTarget-", delete=False) as tmp_file:
        tmp_file.close()
        target = Target()
        target.path = pathlib.Path(tmp_file.name)
        yield target


def make_os_target(
    tmp_path: pathlib.Path,
    os_plugin: type[OSPlugin],
    root_fs: Filesystem | None = None,
    apply_target: bool = True,
) -> Target:
    mock_target = next(make_mock_target(tmp_path))
    mock_target._os_plugin = os_plugin

    if root_fs is not None:
        mock_target.filesystems.add(root_fs)

    if apply_target:
        mock_target.apply()

    return mock_target


@pytest.fixture
def make_mock_targets(request: pytest.FixtureRequest, tmp_path: pathlib.Path) -> Callable[[int], Iterator[Target]]:
    def _make_targets(size: int) -> Iterator[Target]:
        for _ in range(size):
            yield from make_mock_target(tmp_path)

    return _make_targets


@pytest.fixture
def fs_win(tmp_path: pathlib.Path) -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem(case_sensitive=False, alt_separator="\\")
    fs.map_dir("windows/system32", tmp_path)
    fs.map_dir("windows/system32/config/", tmp_path)
    yield fs


@pytest.fixture
def fs_unix() -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc")
    yield fs


@pytest.fixture
def fs_linux() -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc")
    fs.makedirs("opt")
    yield fs


@pytest.fixture
def fs_debian() -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc/dpkg")
    fs.makedirs("opt")
    yield fs


@pytest.fixture
def fs_redhat() -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc/sysconfig/network-scripts")
    fs.makedirs("opt")
    yield fs


@pytest.fixture
def fs_suse() -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc/zypp")
    fs.makedirs("opt")
    yield fs


@pytest.fixture
def fs_linux_sys(fs_linux: VirtualFilesystem) -> Iterator[VirtualFilesystem]:
    fs_linux.makedirs("sys")
    yield fs_linux


@pytest.fixture
def fs_linux_proc(fs_linux: VirtualFilesystem) -> Iterator[VirtualFilesystem]:
    fs = fs_linux

    procs = (
        (
            "proc/1",
            VirtualSymlink(fs, "/proc/1/fd/4", "socket:[1337]"),
            "test\x00cmdline\x00",
            "VAR=1",
        ),
        (
            "proc/2",
            VirtualSymlink(fs, "/proc/2/fd/4", "socket:[1338]"),
            "\x00",
            "VAR=1\x00",
        ),
        (
            "proc/3",
            VirtualSymlink(fs, "/proc/3/fd/4", "socket:[1339]"),
            "sshd",
            "VAR=1",
        ),
        (
            "proc/1337",
            VirtualSymlink(fs, "/proc/1337/fd/4", "socket:[1337]"),
            "acquire\x00-p\x00full\x00--proc\x00",
            "VAR=1",
        ),
    )
    stat_files_data = (
        "1 (systemd) S 0 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "2 (kthread) K 1 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "3 (sshd) W 1 2 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
        "1337 (acquire) R 3 1 1 0 -1 4194560 53787 457726 166 4255 112 260 761 548 20 0 1 0 30 184877056 2658 18446744073709551615 93937510957056 93937511789581 140726499200496 0 0 0 671173123 4096 1260 0 0 0 17 0 0 0 11 0 0 93937512175824 93937512476912 93937519890432 140726499204941 140726499204952 140726499204952 140726499205101 0\n",  # noqa
    )

    for idx, proc in enumerate(procs):
        dir, fd, cmdline, environ = proc
        fs.makedirs(dir)
        fs.map_file_entry(fd.path, fd)

        fs.map_file_fh(dir + "/stat", BytesIO(stat_files_data[idx].encode()))
        fs.map_file_fh(dir + "/cmdline", BytesIO(cmdline.encode()))
        fs.map_file_fh(dir + "/environ", BytesIO(environ.encode()))

    # symlink acquire process to self
    fs.link("/proc/1337", "/proc/self")

    # boottime and uptime are needed for for time tests
    fs.map_file_fh("/proc/uptime", BytesIO(b"134368.27 132695.52\n"))
    fs.map_file_fh("/proc/stat", BytesIO(b"btime 1680559854"))

    yield fs


@pytest.fixture
def fs_linux_proc_sockets(fs_linux_proc: VirtualFilesystem) -> Iterator[VirtualFilesystem]:
    fs = fs_linux_proc

    for filename in ("unix", "packet", "raw6", "raw", "udp6", "udp", "tcp6", "tcp"):
        fs.map_file(f"/proc/net/{filename}", absolute_path(f"_data/plugins/os/unix/linux/proc/net/{filename}"))

    yield fs


@pytest.fixture
def fs_osx() -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem()
    fs.makedirs("Applications")
    fs.makedirs("Library")
    yield fs


@pytest.fixture
def fs_bsd() -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem()
    fs.map_file("/bin/freebsd-version", absolute_path("_data/plugins/os/unix/bsd/freebsd/freebsd-freebsd-version"))
    yield fs


@pytest.fixture
def fs_android() -> Iterator[VirtualFilesystem]:
    fs = VirtualFilesystem()
    fs.map_file("/build.prop", absolute_path("_data/plugins/os/unix/linux/android/build.prop"))
    yield fs


@pytest.fixture
def hive_hklm() -> Iterator[VirtualHive]:
    hive = VirtualHive()

    # set current control set to ControlSet001 and mock it
    controlset_key = "SYSTEM\\ControlSet001"
    hive.map_key(controlset_key, VirtualKey(hive, controlset_key))

    select_key = "SYSTEM\\Select"
    hive.map_key(select_key, VirtualKey(hive, select_key))
    hive.map_value(select_key, "Current", VirtualValue(hive, "Current", 1))

    yield hive


@pytest.fixture
def hive_hku() -> Iterator[VirtualHive]:
    hive = VirtualHive()

    yield hive


@pytest.fixture
def target_bare(tmp_path: pathlib.Path) -> Iterator[Target]:
    # A target without any associated OSPlugin
    yield from make_mock_target(tmp_path)


@pytest.fixture
def target_default(tmp_path: pathlib.Path) -> Iterator[Target]:
    yield make_os_target(tmp_path, default.DefaultPlugin)


@pytest.fixture
def target_win(tmp_path: pathlib.Path, hive_hklm: VirtualHive, fs_win: Filesystem) -> Iterator[Target]:
    mock_target = make_os_target(tmp_path, WindowsPlugin, root_fs=fs_win, apply_target=False)

    mock_target.add_plugin(registry.RegistryPlugin, check_compatible=False)
    mock_target.registry.add_hive(
        "HKEY_LOCAL_MACHINE",
        "HKEY_LOCAL_MACHINE",
        hive_hklm,
        TargetPath(mock_target.fs, ""),
    )
    mock_target.fs.mount("c:", fs_win)

    mock_target.apply()

    yield mock_target


@pytest.fixture
def target_unix(tmp_path: pathlib.Path, fs_unix: Filesystem) -> Iterator[Target]:
    yield make_os_target(tmp_path, UnixPlugin, root_fs=fs_unix)


@pytest.fixture
def target_linux(tmp_path: pathlib.Path, fs_linux: Filesystem) -> Iterator[Target]:
    yield make_os_target(tmp_path, LinuxPlugin, root_fs=fs_linux)


@pytest.fixture
def target_debian(tmp_path: pathlib.Path, fs_debian: Filesystem) -> Iterator[Target]:
    yield make_os_target(tmp_path, DebianPlugin, root_fs=fs_debian)


@pytest.fixture
def target_redhat(tmp_path: pathlib.Path, fs_redhat: Filesystem) -> Iterator[Target]:
    yield make_os_target(tmp_path, RedHatPlugin, root_fs=fs_redhat)


@pytest.fixture
def target_suse(tmp_path: pathlib.Path, fs_suse: Filesystem) -> Iterator[Target]:
    yield make_os_target(tmp_path, SuSEPlugin, root_fs=fs_suse)


@pytest.fixture
def target_osx(tmp_path: pathlib.Path, fs_osx: Filesystem) -> Iterator[Target]:
    mock_target = make_os_target(tmp_path, MacPlugin, root_fs=fs_osx)

    version = absolute_path("_data/plugins/os/unix/bsd/osx/_os/SystemVersion.plist")
    fs_osx.map_file("/System/Library/CoreServices/SystemVersion.plist", version)

    system = absolute_path("_data/plugins/os/unix/bsd/osx/_os/preferences.plist")
    fs_osx.map_file("/Library/Preferences/SystemConfiguration/preferences.plist", system)

    yield mock_target


@pytest.fixture
def target_citrix(tmp_path: pathlib.Path, fs_bsd: VirtualFilesystem) -> Target:
    mock_target = next(make_mock_target(tmp_path))
    mock_target._os_plugin = CitrixPlugin

    mock_target.filesystems.add(fs_bsd)

    var_filesystem = VirtualFilesystem()
    var_filesystem.makedirs("/netscaler")
    var_filesystem.makedirs("/log")
    mock_target.filesystems.add(var_filesystem)

    flash_filesystem = VirtualFilesystem()
    flash_filesystem.map_dir("/", absolute_path("_data/plugins/os/unix/bsd/citrix/_os/flash"))
    mock_target.filesystems.add(flash_filesystem)

    mock_target.apply()
    yield mock_target


@pytest.fixture
def target_android(tmp_path: pathlib.Path, fs_android: Filesystem) -> Iterator[Target]:
    yield make_os_target(tmp_path, AndroidPlugin, root_fs=fs_android)


@pytest.fixture
def target_win_users(hive_hklm: VirtualHive, hive_hku: VirtualHive, target_win: Target) -> Iterator[Target]:
    profile_list_key_name = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    profile_list_key = VirtualKey(hive_hklm, profile_list_key_name)

    sid_local_system = "S-1-5-18"
    profile1_key = VirtualKey(hive_hklm, f"{profile_list_key_name}\\{sid_local_system}")
    profile1_key.add_value(
        "ProfileImagePath", VirtualValue(hive_hklm, "ProfileImagePath", "%systemroot%\\system32\\config\\systemprofile")
    )

    sid_users_john = "S-1-5-21-3263113198-3007035898-945866154-1002"
    profile2_key = VirtualKey(hive_hklm, f"{profile_list_key_name}\\{sid_users_john}")
    profile2_key.add_value("ProfileImagePath", VirtualValue(hive_hklm, "ProfileImagePath", "C:\\Users\\John"))

    profile_list_key.add_subkey(sid_local_system, profile1_key)
    profile_list_key.add_subkey(sid_users_john, profile2_key)

    hive_hklm.map_key(profile_list_key_name, profile_list_key)

    target_win.registry.add_hive("HKEY_USERS", f"HKEY_USERS\\{sid_users_john}", hive_hku, TargetPath(target_win.fs, ""))

    yield target_win


SYSTEM_KEY_PATH = "SYSTEM\\ControlSet001\\Control\\LSA"
POLICY_KEY_PATH = "SECURITY\\Policy\\PolEKList"
DPAPI_KEY_PATH = "SECURITY\\Policy\\Secrets\\DPAPI_SYSTEM\\CurrVal"


@pytest.fixture
def target_win_users_dpapi(
    hive_hklm: VirtualHive, hive_hku: VirtualHive, fs_win: VirtualFilesystem, target_win: Target
) -> Iterator[Target]:
    # Add User
    profile_list_key_name = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    profile_list_key = VirtualKey(hive_hklm, profile_list_key_name)

    sid_local_system = "S-1-5-18"
    profile1_key = VirtualKey(hive_hklm, f"{profile_list_key_name}\\{sid_local_system}")
    profile1_key.add_value(
        "ProfileImagePath", VirtualValue(hive_hklm, "ProfileImagePath", "%systemroot%\\system32\\config\\systemprofile")
    )

    sid_user = "S-1-5-21-1342509979-482553916-3960431919-1000"
    profile2_key = VirtualKey(hive_hklm, f"{profile_list_key_name}\\{sid_user}")
    profile2_key.add_value("ProfileImagePath", VirtualValue(hive_hklm, "ProfileImagePath", "C:\\Users\\user"))

    profile_list_key.add_subkey(sid_local_system, profile1_key)
    profile_list_key.add_subkey(sid_user, profile2_key)

    hive_hklm.map_key(profile_list_key_name, profile_list_key)

    target_win.registry.add_hive("HKEY_USERS", f"HKEY_USERS\\{sid_user}", hive_hku, TargetPath(target_win.fs, ""))

    # Add system dpapi files
    fs_win.map_dir(
        "Windows/System32/Microsoft/Protect", absolute_path("_data/plugins/os/windows/dpapi/fixture/Protect_System32")
    )

    # Add user dpapi files
    fs_win.map_dir(
        "Users/User/AppData/Roaming/Microsoft/Protect",
        absolute_path("_data/plugins/os/windows/dpapi/fixture/Protect_User"),
    )

    # Add registry dpapi keys
    system_key = VirtualKey(hive_hklm, SYSTEM_KEY_PATH)
    system_key.add_subkey("Data", VirtualKey(hive_hklm, "Data", class_name="8fa8e1fb"))
    system_key.add_subkey("GBG", VirtualKey(hive_hklm, "GBG", class_name="a6e23eb8"))
    system_key.add_subkey("JD", VirtualKey(hive_hklm, "JD", class_name="fe5ffdaf"))
    system_key.add_subkey("Skew1", VirtualKey(hive_hklm, "Skew1", class_name="6e289261"))
    hive_hklm.map_key(SYSTEM_KEY_PATH, system_key)

    policy_key = VirtualKey(hive_hklm, POLICY_KEY_PATH)
    policy_key_value = b"\x00\x00\x00\x01\xec\xff\xe1{*\x99t@\xaa\x93\x9a\xdb\xff&\xf1\xfc\x03\x00\x00\x00\x00\x00\x00\x00goX67\xc3\xe0\xe7\xb9\xed\xf4;;)\xb1\xd0\xd2L\xb6\xbf\xc6\x0e\x0f\xc4\xdcDn}$M053\xb9\n+\xd72\xfc\xf9\x85t\x8a\x89\x17\xae\xa7>\x9d\x0b)\x0e\xe4\xba/S\xe6\xa9\xa0\xac\x9b<\x9b&\xe7!\xb0\x1bzl\x1f\x92\xb5\x17\xe2\xa3?_m\xe7\xf76qg\x93\xb1\x98r\x05\x95\x95\xe6\xb4\xdc\x88\x8d\x19\xd1\xd6\x15\xd6\x02\xbe\xd5SG\x8cA\x1d/\xed\x04V\x02\xdd\xbbZ\xdc1\xc9\x90\x10!\xad3\x9b\xca6\x8b\xdbUO\xfe\x07JptR\x8d^\x9d\xcb\xb4g"  # noqa
    policy_key.add_value("(Default)", policy_key_value)
    hive_hklm.map_key(POLICY_KEY_PATH, policy_key)

    secrets_key = VirtualKey(hive_hklm, DPAPI_KEY_PATH)
    secrets_key_value = b"\x00\x00\x00\x01|>q\xec\xa8\xfbN\xed\x03\xeaCa\xfb\xc7\x83\x87\x03\x00\x00\x00\x00\x00\x00\x00\xafd\xca2\xa1PY\xf8\xe3\x8f2\x8a_\x16\xd0c\x93\x9b\xdb\xb92\x1b\xa1Y\xdc\xaf\xd9\xcd\xf3\x16\xd8/\x89\xa8)\xd7X\x02K'm\t\x9e\xf2)\x0c\xa4o\xc7\xb2cUhP\x0b\xf2\xd3\x1e\xd8\xce\x1e\x0304\\\xca^\xf3\xe8\xd1\x83\x99\xa2*\xe8\x8d\xb1(r\xee[\xb0\xc1\xf0\xdd;\x83\x06bi\xd0\xd9a\x8b\x19\xbb"  # noqa
    secrets_key.add_value("(Default)", secrets_key_value)
    hive_hklm.map_key(DPAPI_KEY_PATH, secrets_key)

    target_win.add_plugin(DPAPIPlugin)

    yield target_win


@pytest.fixture
def target_win_tzinfo(hive_hklm: VirtualHive, target_win: Target) -> Iterator[Target]:
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
def target_win_tzinfo_legacy(hive_hklm: VirtualHive, target_win: Target) -> Iterator[Target]:
    tz_info_path = "SYSTEM\\ControlSet001\\Control\\TimeZoneInformation"
    tz_info = VirtualKey(hive_hklm, tz_info_path)
    tz_info.add_value("StandardName", "Paaseiland")

    east_tz_data_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\Easter Island Standard Time"
    east_tz_data = VirtualKey(hive_hklm, east_tz_data_path)
    east_tz_data.add_value("Display", "(UTC-06:00) Easter Island")
    east_tz_data.add_value("Dlt", "Easter Island Daylight Time")
    east_tz_data.add_value("Std", "Paaseiland")
    east_tzi = bytes.fromhex("6801000000000000c4ffffff0000040006000100160000000000000000000900060001001600000000000000")
    east_tz_data.add_value("TZI", east_tzi)

    hive_hklm.map_key(tz_info_path, tz_info)
    hive_hklm.map_key(east_tz_data_path, east_tz_data)

    yield target_win


@pytest.fixture
def target_unix_users(target_unix: Target, fs_unix: Filesystem) -> Iterator[Target]:
    passwd = """
    root:x:0:0:root:/root:/bin/bash
    user:x:1000:1000:user:/home/user:/bin/bash
    """
    fs_unix.map_file_fh("/etc/passwd", BytesIO(textwrap.dedent(passwd).encode()))
    yield target_unix


@pytest.fixture
def target_linux_users(target_linux: Target, fs_linux: VirtualFilesystem) -> Iterator[Target]:
    passwd = """
    root:x:0:0:root:/root:/bin/bash
    user:x:1000:1000:user:/home/user:/bin/bash
    """
    fs_linux.map_file_fh("/etc/passwd", BytesIO(textwrap.dedent(passwd).encode()))
    yield target_linux


@pytest.fixture
def target_osx_users(target_osx: Target, fs_osx: VirtualFilesystem) -> Iterator[Target]:
    dissect = absolute_path("_data/plugins/os/unix/bsd/osx/_os/dissect.plist")
    fs_osx.map_file("/var/db/dslocal/nodes/Default/users/_dissect.plist", dissect)

    test = absolute_path("_data/plugins/os/unix/bsd/osx/_os/test.plist")
    fs_osx.map_file("/var/db/dslocal/nodes/Default/users/_test.plist", test)

    yield target_osx


@pytest.fixture
def fs_docker() -> Iterator[TarFilesystem]:
    docker_tar = pathlib.Path(absolute_path("_data/plugins/apps/container/docker/docker.tgz"))
    fh = docker_tar.open("rb")
    docker_fs = TarFilesystem(fh)
    yield docker_fs


@pytest.fixture
def target_linux_docker(tmp_path: pathlib.Path, fs_docker: TarFilesystem) -> Iterator[Target]:
    mock_target = next(make_mock_target(tmp_path))
    mock_target._os_plugin = LinuxPlugin

    mock_target.filesystems.add(fs_docker)
    mock_target.fs.mount("/", fs_docker)
    mock_target.apply()
    yield mock_target
