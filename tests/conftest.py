import pathlib
import tempfile
import textwrap
from io import BytesIO

import pytest

from dissect.target.filesystem import VirtualFilesystem, VirtualSymlink
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
def fs_unix_proc(fs_unix):
    fs = fs_unix

    procs = (
        ("proc/1", VirtualSymlink(fs, "/proc/1/fd/4", "socket:[1337]"), "test\x00cmdline\x00", "VAR=1"),
        ("proc/2", VirtualSymlink(fs, "/proc/2/fd/4", "socket:[1338]"), "\x00", "VAR=1\x00"),
        ("proc/3", VirtualSymlink(fs, "/proc/3/fd/4", "socket:[1339]"), "sshd", "VAR=1"),
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
def fs_unix_proc_sockets(fs_unix_proc):
    fs = fs_unix_proc

    tcp_socket_data = """sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1337 1 000000000e5941ba 100 0 0 10 0
1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1338 1 000000008b915f09 100 0 0 10 0
2: 884010AC:0016 014010AC:C122 01 00000000:00000000 02:00010C92 00000000     0        0 0
"""  # noqa: E501

    tcp6_socket_data = """sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n
0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1337 1 0000000085d2a181 100 0 0 10 0\n   
1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1338 1 00000000bb201f51 100 0 0 10 0\n
"""  # noqa: E501

    udp_socket_data = """sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n  
344: 884010AC:0044 FE4010AC:0043 01 00000000:00000000 00:00000000 00000000     0        0 1337 2 00000000c414b4d1 0\n  
477: 00000000:E4C9 00000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 1338 2 000000009ce0849c 0\n  
509: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 1339 2 00000000388d9bb8 0\n  
"""  # noqa: E501

    udp6_socket_data = """sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n  
497: 00000000000000000000000000000000:E8DD 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 1337 2 00000000bb422355 0\n
509: 00000000000000000000000000000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000   110        0 1338 2 000000005c20ab36 0\n
"""  # noqa: E501

    raw_socket_data = """sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n
253: 00000000:00FD 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1337 2 00000000f7e50cca 0\n
"""  # noqa: E501

    raw6_socket_data = """sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n   
58: 00000000000000000000000000000000:003A 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1337 2 00000000fa98d32c 0\n
"""  # noqa: E501

    packet_socket_data = """sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n
00000000819f8865 3      3    0003   2     1 0      0      1337\n
"""
    unix_socket_data = """Num       RefCount Protocol Flags    Type St Inode Path\n
00000000a6061ba5: 00000002 00000000 00010000 0001 01 1337 /run/systemd/private\n
0000000065bb3d75: 00000003 00000000 00000000 0001 03 1338\n
000000008d0bfa50: 00000002 00000000 00010000 0001 01 1339 /run/systemd/io.system.ManagedOOM\n
00000000fb54422c: 00000002 00000000 00010000 0001 01 0 @/tmp/dbus-YLq1FHVh\n
"""

    fs.map_file_fh("/proc/net/unix", BytesIO(textwrap.dedent(unix_socket_data).encode()))
    fs.map_file_fh("/proc/net/packet", BytesIO(textwrap.dedent(packet_socket_data).encode()))
    fs.map_file_fh("/proc/net/raw6", BytesIO(textwrap.dedent(raw6_socket_data).encode()))
    fs.map_file_fh("/proc/net/raw", BytesIO(textwrap.dedent(raw_socket_data).encode()))
    fs.map_file_fh("/proc/net/udp6", BytesIO(textwrap.dedent(udp6_socket_data).encode()))
    fs.map_file_fh("/proc/net/udp", BytesIO(textwrap.dedent(udp_socket_data).encode()))
    fs.map_file_fh("/proc/net/tcp6", BytesIO(textwrap.dedent(tcp6_socket_data).encode()))
    fs.map_file_fh("/proc/net/tcp", BytesIO(textwrap.dedent(tcp_socket_data).encode()))

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
