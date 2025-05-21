from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import textwrap
from io import BytesIO
from typing import TYPE_CHECKING, Callable

import pytest

from dissect.target.exceptions import RegistryKeyNotFoundError
from dissect.target.filesystem import Filesystem, VirtualFilesystem, VirtualSymlink
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers import keychain
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugin import _generate_long_paths
from dissect.target.plugins.os.default._os import DefaultOSPlugin
from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.plugins.os.unix.bsd.citrix._os import CitrixPlugin
from dissect.target.plugins.os.unix.bsd.darwin.ios._os import IOSPlugin
from dissect.target.plugins.os.unix.bsd.darwin.macos._os import MacOSPlugin
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from dissect.target.plugins.os.unix.linux.debian._os import DebianPlugin
from dissect.target.plugins.os.unix.linux.redhat._os import RedHatPlugin
from dissect.target.plugins.os.unix.linux.suse._os import SuSEPlugin
from dissect.target.plugins.os.windows import registry
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.plugin import OSPlugin


HAS_BENCHMARK = importlib.util.find_spec("pytest_benchmark") is not None


def pytest_configure(config: pytest.Config) -> None:
    if not HAS_BENCHMARK:
        # If we don't have pytest-benchmark (or pytest-codspeed) installed, register the benchmark marker ourselves
        # to avoid pytest warnings
        config.addinivalue_line("markers", "benchmark: mark test for benchmarking (requires pytest-benchmark)")


def pytest_sessionstart(session: pytest.Session) -> None:
    # Test if the _data/ directory is present and if not, as is the case in Python
    # source distributions of dissect.target, we give an error
    data_dir = absolute_path("_data")
    if not data_dir.is_dir():
        session.shouldfail = (
            "! !\n"
            f"No test data directory {data_dir} found.\n"
            "This can happen when you have downloaded the source distribution\n"
            "of dissect.target from pypi.org. If so, retrieve the test data from\n"
            "the dissect.target GitHub repository at:\n"
            "https://github.com/fox-it/dissect.target"
            "\n! !"
        )
    else:
        # Test if the test data looks like LFS references and if so, we give an error
        # This can happen when git-lfs is not installed or not configured correctly
        for file in (path for path in data_dir.rglob("*") if path.is_file()):
            with file.open("rb") as fh:
                if fh.read(42) == b"version https://git-lfs.github.com/spec/v1":
                    session.shouldfail = (
                        "! !\n"
                        "Test data files look like git-lfs references.\n"
                        "This can happen when git-lfs is not installed or not configured correctly.\n"
                        "Install git-lfs and run: \n"
                        "git lfs install && git lfs pull"
                        "\n! !"
                    )
            break


def pytest_runtest_setup(item: pytest.Item) -> None:
    if not HAS_BENCHMARK and item.get_closest_marker("benchmark") is not None:
        pytest.skip("pytest-benchmark is not installed")


@pytest.fixture(autouse=True)
def clear_caches() -> None:
    _generate_long_paths.cache_clear()


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
def fs_win(tmp_path: pathlib.Path) -> VirtualFilesystem:
    fs = VirtualFilesystem(case_sensitive=False, alt_separator="\\")
    fs.map_dir("windows/system32", tmp_path)
    fs.map_dir("windows/system32/config/", tmp_path)
    return fs


@pytest.fixture
def fs_unix() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc")
    return fs


@pytest.fixture
def fs_linux() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc")
    fs.makedirs("opt")
    return fs


@pytest.fixture
def fs_debian() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc/dpkg")
    fs.makedirs("opt")
    return fs


@pytest.fixture
def fs_redhat() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc/sysconfig/network-scripts")
    fs.makedirs("opt")
    return fs


@pytest.fixture
def fs_suse() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc/zypp")
    fs.makedirs("opt")
    return fs


@pytest.fixture
def fs_linux_sys(fs_linux: VirtualFilesystem) -> VirtualFilesystem:
    fs_linux.makedirs("sys")
    return fs_linux


@pytest.fixture
def fs_linux_proc(fs_linux: VirtualFilesystem) -> VirtualFilesystem:
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

    return fs


@pytest.fixture
def fs_linux_proc_sockets(fs_linux_proc: VirtualFilesystem) -> VirtualFilesystem:
    fs = fs_linux_proc

    for filename in ("unix", "packet", "raw6", "raw", "udp6", "udp", "tcp6", "tcp"):
        fs.map_file(f"/proc/net/{filename}", absolute_path(f"_data/plugins/os/unix/linux/proc/net/{filename}"))

    return fs


@pytest.fixture
def fs_macos() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.makedirs("Applications")
    fs.makedirs("Library")
    return fs


@pytest.fixture
def fs_ios() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.makedirs("/private/var/preferences")
    fs.makedirs("/private/var/mobile")
    return fs


@pytest.fixture
def fs_bsd() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.map_file("/bin/freebsd-version", absolute_path("_data/plugins/os/unix/bsd/freebsd/freebsd-freebsd-version"))
    return fs


@pytest.fixture
def fs_android() -> VirtualFilesystem:
    fs = VirtualFilesystem()
    fs.makedirs("/data")
    fs.makedirs("/system")
    fs.makedirs("/vendor")
    fs.makedirs("/product")
    fs.map_file("/build.prop", absolute_path("_data/plugins/os/unix/linux/android/build.prop"))
    return fs


@pytest.fixture
def hive_hklm() -> VirtualHive:
    hive = VirtualHive()

    # set current control set to ControlSet001 and mock it
    change_controlset(hive, 1)

    return hive


def change_controlset(hive: VirtualHive, num: int) -> None:
    """Update the current control set of the given HKLM hive."""

    if not isinstance(num, int) or num > 999 or num < 1:
        raise ValueError("ControlSet integer must be between 1 and 999")

    controlset_key = f"SYSTEM\\ControlSet{num:>03}"
    hive.map_key(controlset_key, VirtualKey(hive, controlset_key))

    select_key = "SYSTEM\\Select"
    hive.map_key(select_key, VirtualKey(hive, select_key))
    hive.map_value(select_key, "Current", VirtualValue(hive, "Current", num))


@pytest.fixture
def hive_hku() -> VirtualHive:
    return VirtualHive()


@pytest.fixture
def target_bare(tmp_path: pathlib.Path) -> Iterator[Target]:
    # A target without any associated OSPlugin
    yield from make_mock_target(tmp_path)


@pytest.fixture
def target_default(tmp_path: pathlib.Path) -> Target:
    return make_os_target(tmp_path, DefaultOSPlugin)


@pytest.fixture
def target_win(tmp_path: pathlib.Path, hive_hklm: VirtualHive, fs_win: Filesystem) -> Target:
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

    return mock_target


@pytest.fixture
def target_unix(tmp_path: pathlib.Path, fs_unix: Filesystem) -> Target:
    return make_os_target(tmp_path, UnixPlugin, root_fs=fs_unix)


@pytest.fixture
def target_linux(tmp_path: pathlib.Path, fs_linux: Filesystem) -> Target:
    return make_os_target(tmp_path, LinuxPlugin, root_fs=fs_linux)


@pytest.fixture
def target_debian(tmp_path: pathlib.Path, fs_debian: Filesystem) -> Target:
    return make_os_target(tmp_path, DebianPlugin, root_fs=fs_debian)


@pytest.fixture
def target_redhat(tmp_path: pathlib.Path, fs_redhat: Filesystem) -> Target:
    return make_os_target(tmp_path, RedHatPlugin, root_fs=fs_redhat)


@pytest.fixture
def target_suse(tmp_path: pathlib.Path, fs_suse: Filesystem) -> Target:
    return make_os_target(tmp_path, SuSEPlugin, root_fs=fs_suse)


@pytest.fixture
def target_macos(tmp_path: pathlib.Path, fs_macos: Filesystem) -> Target:
    mock_target = make_os_target(tmp_path, MacOSPlugin, root_fs=fs_macos)

    version = absolute_path("_data/plugins/os/unix/bsd/darwin/macos/_os/SystemVersion.plist")
    fs_macos.map_file("/System/Library/CoreServices/SystemVersion.plist", version)

    system = absolute_path("_data/plugins/os/unix/bsd/darwin/macos/_os/preferences.plist")
    fs_macos.map_file("/Library/Preferences/SystemConfiguration/preferences.plist", system)

    return mock_target


@pytest.fixture
def target_ios(tmp_path: pathlib.Path, fs_ios: Filesystem) -> Target:
    return make_os_target(tmp_path, IOSPlugin, root_fs=fs_ios)


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
    return mock_target


@pytest.fixture
def target_android(tmp_path: pathlib.Path, fs_android: Filesystem) -> Target:
    return make_os_target(tmp_path, AndroidPlugin, root_fs=fs_android)


def add_win_user(hive_hklm: VirtualHive, hive_hku: VirtualHive, target_win: Target, sid: str, home: str) -> None:
    """Add a user to the provided Windows target."""

    profile_list_key_name = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    try:
        profile_list_key = hive_hklm.key(profile_list_key_name)
    except RegistryKeyNotFoundError:
        profile_list_key = VirtualKey(hive_hklm, profile_list_key_name)

    try:
        hive_hklm.key(f"{profile_list_key_name}\\{sid}")
        raise ValueError(f"User with SID {sid} already exists!")
    except RegistryKeyNotFoundError:
        pass

    profile_key = VirtualKey(hive_hklm, f"{profile_list_key_name}\\{sid}")
    profile_key.add_value("ProfileImagePath", VirtualValue(hive_hklm, "ProfileImagePath", home))
    profile_list_key.add_subkey(sid, profile_key)

    hive_hklm.map_key(profile_list_key_name, profile_list_key)

    if sid != "S-1-5-18":
        target_win.registry.add_hive("HKEY_USERS", f"HKEY_USERS\\{sid}", hive_hku, TargetPath(target_win.fs, ""))


@pytest.fixture
def target_win_users(hive_hklm: VirtualHive, hive_hku: VirtualHive, target_win: Target) -> Target:
    """Minimal Windows target with a SYSTEM user and local user John."""
    add_win_user(hive_hklm, hive_hku, target_win, sid="S-1-5-18", home="%systemroot%\\system32\\config\\systemprofile")
    add_win_user(
        hive_hklm, hive_hku, target_win, sid="S-1-5-21-3263113198-3007035898-945866154-1002", home="C:\\Users\\John"
    )
    return target_win


@pytest.fixture
def target_win_tzinfo(hive_hklm: VirtualHive, target_win: Target) -> Target:
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

    utc_tz_data_path = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\UTC"
    utc_tz_data = VirtualKey(hive_hklm, utc_tz_data_path)
    utc_tz_data.add_value("Display", "(UTC) Coordinated Universal Time")
    utc_tz_data.add_value("Dlt", "Coordinated Universal Time")
    utc_tz_data.add_value("Std", "Coordinated Universal Time")
    utc_tz_data.add_value("TZI", b"\x00" * 44)

    dynamic_dst = VirtualKey(hive_hklm, east_tz_data_path + "\\Dynamic DST")
    dynamic_dst.add_value("FirstEntry", 2019)
    dynamic_dst.add_value("LastEntry", 2019)
    tzi_2019 = bytes.fromhex("6801000000000000c4ffffff0000040006000100160000000000000000000900060001001600000000000000")
    dynamic_dst.add_value("2019", tzi_2019)
    east_tz_data.add_subkey("Dynamic DST", dynamic_dst)

    hive_hklm.map_key(tz_info_path, tz_info)
    hive_hklm.map_key(eu_tz_data_path, eu_tz_data)
    hive_hklm.map_key(east_tz_data_path, east_tz_data)
    hive_hklm.map_key(utc_tz_data_path, utc_tz_data)

    return target_win


@pytest.fixture
def target_win_tzinfo_legacy(hive_hklm: VirtualHive, target_win: Target) -> Target:
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

    return target_win


@pytest.fixture
def target_unix_users(target_unix: Target, fs_unix: Filesystem) -> Target:
    passwd = """
    root:x:0:0:root:/root:/bin/bash
    user:x:1000:1000:user:/home/user:/bin/bash
    +@ngtest:x:::::
    """
    fs_unix.map_file_fh("/etc/passwd", BytesIO(textwrap.dedent(passwd).encode()))
    return target_unix


@pytest.fixture
def target_linux_users(target_linux: Target, fs_linux: VirtualFilesystem) -> Target:
    passwd = """
    root:x:0:0:root:/root:/bin/bash
    user:x:1000:1000:user:/home/user:/bin/bash
    """
    fs_linux.map_file_fh("/etc/passwd", BytesIO(textwrap.dedent(passwd).encode()))
    return target_linux


@pytest.fixture
def target_macos_users(target_macos: Target, fs_macos: VirtualFilesystem) -> Target:
    dissect = absolute_path("_data/plugins/os/unix/bsd/darwin/macos/_os/dissect.plist")
    fs_macos.map_file("/var/db/dslocal/nodes/Default/users/_dissect.plist", dissect)

    test = absolute_path("_data/plugins/os/unix/bsd/darwin/macos/_os/test.plist")
    fs_macos.map_file("/var/db/dslocal/nodes/Default/users/_test.plist", test)

    fs_macos.makedirs("/Users/dissect")

    return target_macos


@pytest.fixture
def fs_docker() -> TarFilesystem:
    docker_tar = pathlib.Path(absolute_path("_data/plugins/apps/container/docker/docker.tgz"))
    fh = docker_tar.open("rb")
    return TarFilesystem(fh)


@pytest.fixture
def target_linux_docker(tmp_path: pathlib.Path, fs_docker: TarFilesystem) -> Target:
    mock_target = next(make_mock_target(tmp_path))
    mock_target._os_plugin = LinuxPlugin

    mock_target.filesystems.add(fs_docker)
    mock_target.fs.mount("/", fs_docker)
    mock_target.apply()
    return mock_target


class TargetUnixFactory:
    def __init__(self, tmp_path: pathlib.Path):
        self.tmp_path = tmp_path

    def new(self, hostname: str = "hostname") -> tuple[Target, VirtualFilesystem]:
        """Initialize a virtual unix target."""
        fs = VirtualFilesystem()

        fs.makedirs("var")
        fs.makedirs("etc")
        fs.map_file_fh("/etc/hostname", BytesIO(hostname.encode()))

        return make_os_target(self.tmp_path, UnixPlugin, root_fs=fs), fs


@pytest.fixture
def target_unix_factory(tmp_path: pathlib.Path) -> TargetUnixFactory:
    """This fixture returns a class that can instantiate a virtual unix targets from a blueprint. This can then be used
    to create a fixture for the source target and the desination target, without them 'bleeding' into each other."""
    return TargetUnixFactory(tmp_path)


@pytest.fixture
def guarded_keychain() -> Iterator[None]:
    """This fixture clears the keychain from any previously added values."""
    keychain.KEYCHAIN.clear()
    yield
    keychain.KEYCHAIN.clear()
