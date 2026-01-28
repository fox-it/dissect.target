from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.log.utmp import UtmpPlugin, WtmpDbEntryType
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_utmp_ipv6(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/log/btmp/btmp-ipv6")
    fs_linux.map_file("var/log/btmp", data_file)

    target_linux.add_plugin(UtmpPlugin)

    results = list(target_linux.btmp())
    assert len(results) == 6

    # IPv4 address
    assert results[0].ut_host == "127.0.0.1"
    assert results[0].ut_addr == "127.0.0.1"

    # IPv6 address
    assert results[2].ut_host == "1337::1"
    assert results[2].ut_addr == "1337::1"

    # IPv6 address with 12 bytes of trailing zeroes
    assert results[5].ut_host == "1337:1::"
    assert results[5].ut_addr == "1337:1::"


def test_wtmp_plugin(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/log/wtmp/wtmp")
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


def test_btmp_plugin(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/log/btmp/btmp")
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


def test_utmp_plugin(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    """Test if we correctly parse a /var/run/utmp file."""
    fs_linux.map_file("var/run/utmp", absolute_path("_data/plugins/os/unix/log/wtmp/wtmp"))
    target_linux.add_plugin(UtmpPlugin)
    results = list(target_linux.utmp())
    assert len(results) == 70


def test_wtmpdb(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    """Test if we can parse a /var/log/wtmp.db SQLite3 file from libpam-wtmpdb."""

    fs_linux.map_file("/var/log/wtmp.db", absolute_path("_data/plugins/os/unix/log/wtmp/wtmp.db"))
    fs_linux.map_file("/var/lib/wtmpdb/wtmp.db", absolute_path("_data/plugins/os/unix/log/wtmp/wtmp.db"))
    fs_linux.map_file("/var/lib/wtmpdb/wtmp_20261231.db", absolute_path("_data/plugins/os/unix/log/wtmp/wtmp.db"))

    plugin = target_linux.add_plugin(UtmpPlugin)
    results = list(target_linux.wtmp())

    assert len(results) == 3
    assert list(map(str, plugin.wtmp_paths)) == [
        "/var/log/wtmp.db",
        "/var/lib/wtmpdb/wtmp.db",
        "/var/lib/wtmpdb/wtmp_20261231.db",
    ]

    assert results[0].ts == datetime(2026, 1, 28, 13, 13, 52, 776830, tzinfo=timezone.utc)
    assert not results[0].ts_logout  # user is still logged in
    assert results[0].ut_type == WtmpDbEntryType.USER_PROCESS.name
    assert results[0].ut_user == "root"
    assert results[0].ut_line == "pts/0"
    assert not results[0].ut_host
    assert not results[0].ut_addr
    assert results[0].ut_service == "su"
    assert results[0].source == "/var/log/wtmp.db"
    assert results[0].hostname == "localhost"

    assert results[1].ts == datetime(2026, 1, 28, 13, 13, 52, 776830, tzinfo=timezone.utc)
    assert results[1].ts_logout == datetime(2026, 1, 28, 13, 13, 52, 876830, tzinfo=timezone.utc)
    assert results[1].ut_type == WtmpDbEntryType.USER_PROCESS.name
    assert results[1].ut_user == "root"
    assert results[1].ut_line == "ssh"
    assert results[1].ut_host == "127.0.0.1"
    assert results[1].ut_addr == "127.0.0.1"
    assert results[1].ut_service == "sshd"
    assert results[1].source == "/var/log/wtmp.db"
    assert results[1].hostname == "localhost"
