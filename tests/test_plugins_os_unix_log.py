from datetime import datetime, timezone

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.log.atop import AtopPlugin
from dissect.target.plugins.os.unix.log.lastlog import LastLogPlugin
from dissect.target.plugins.os.unix.log.utmp import UtmpPlugin

from ._utils import absolute_path


def test_utmp_ipv6(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    data_file = absolute_path("data/plugins/os/unix/log/btmp/btmp-ipv6")
    fs_linux.map_file("var/log/btmp", data_file)

    target_linux.add_plugin(UtmpPlugin)

    results = list(target_linux.btmp())

    # IPv4 address
    results[0].ut_host == "127.0.0.1"
    results[0].ut_addr == "127.0.0.1"

    # IPv6 address
    results[4].ut_host == "1337::1"
    results[4].ut_addr == "1337::1"

    # IPv6 address with 12 bytes of trailing zeroes
    results[5].ut_host == "1337:1::"
    results[5].ut_addr == "1337:1::"


def test_wtmp_plugin(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    data_file = absolute_path("data/plugins/os/unix/log/wtmp/wtmp")
    fs_linux.map_file("var/log/wtmp", data_file)

    target_linux.add_plugin(UtmpPlugin)

    results = list(target_linux.wtmp())
    assert len(results) == 70
    result = results[-1]
    assert result.ts == datetime(2021, 11, 12, 10, 12, 54, tzinfo=timezone.utc)
    assert result.ut_type == "USER_PROCESS"
    assert result.ut_user == "traut"
    assert result.ut_pid == 2176
    assert result.ut_line == ":0"
    assert result.ut_id == ""
    assert result.ut_host == ":0"
    assert result.ut_addr == "0.0.0.0"


def test_lastlog_plugin(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    data_file = absolute_path("data/plugins/os/unix/log/lastlog/lastlog")
    fs_linux.map_file("/var/log/lastlog", data_file)

    target_linux.add_plugin(LastLogPlugin)

    results = list(target_linux.lastlog())
    assert len(results) == 1

    assert results[0].ts == datetime(2021, 12, 8, 16, 14, 6, tzinfo=timezone.utc)
    assert results[0].uid == 1001
    assert results[0].ut_user is None
    assert results[0].ut_host == "127.0.0.1"
    assert results[0].ut_tty == "pts/0"


def test_btmp_plugin(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    data_file = absolute_path("data/plugins/os/unix/log/btmp/btmp")
    fs_linux.map_file("var/log/btmp", data_file)

    target_linux.add_plugin(UtmpPlugin)

    results = list(target_linux.btmp())
    assert len(results) == 10
    result = results[-1]
    assert result.ts == datetime(2021, 11, 30, 23, 2, 9, tzinfo=timezone.utc)
    assert result.ut_type == "LOGIN_PROCESS"
    assert result.ut_user == "root"
    assert result.ut_pid == 1865007
    assert result.ut_line == "ssh:notty"
    assert result.ut_id == ""
    assert result.ut_host == "8.210.13.5"
    assert result.ut_addr == "8.210.13.5"


def test_atop_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("data/plugins/os/unix/log/atop/atop")
    fs_unix.map_file("var/log/atop/atop_20221111", data_file)

    target_unix.add_plugin(AtopPlugin)

    results = list(target_unix.atop())
    assert len(results) == 2219
    assert results[0].ts == datetime(2022, 11, 11, 19, 50, 44, tzinfo=timezone.utc)
    assert results[0].process == "systemd"
    assert results[0].cmdline == "/sbin/init"
    assert results[0].tgid == 1
    assert results[0].pid == 1
    assert results[0].ppid == 0
    assert results[0].ruid == 0
    assert results[0].euid == 0
    assert results[0].suid == 0
    assert results[0].fsuid == 0
    assert results[0].rgid == 0
    assert results[0].egid == 0
    assert results[0].sgid == 0
    assert results[0].fsgid == 0
    assert results[0].nthr == 1
    assert bool(results[0].isproc) is True
    assert results[0].state == "S"
    assert results[0].excode == -2147483648
    assert results[0].elaps == 0
    assert results[0].nthrslpi == 1
    assert results[0].nthrslpu == 0
    assert results[0].nthrrun == 0
    assert results[0].ctid == 0
    assert results[0].vpid == 0
    assert bool(results[0].wasinactive) is False
    assert results[0].container == ""
    assert str(results[0].filepath) == "/var/log/atop/atop_20221111"
