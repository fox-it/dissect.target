from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.log.lastlog import LastLogPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_lastlog_sparse(target_linux_users: Target, fs_linux: VirtualFilesystem) -> None:
    """Test if we can correctly parse a sparse lastlog file."""

    data_file = absolute_path("_data/plugins/os/unix/log/lastlog/lastlog")
    fs_linux.map_file("/var/log/lastlog", data_file)

    target_linux_users.add_plugin(LastLogPlugin)

    results = sorted(target_linux_users.lastlog(), key=lambda r: r.ts)
    assert len(results) == 3

    assert results[0].ts == datetime(2021, 12, 8, 16, 14, 6, tzinfo=timezone.utc)
    assert results[0].uid == 1001
    assert results[0].ut_user is None  # since 1001 is not defined in target_linux_users /etc/passwd.
    assert results[0].ut_host == "127.0.0.1"
    assert results[0].ut_tty == "pts/0"
    assert results[0].source == "/var/log/lastlog"

    assert results[1].ts == datetime(2021, 12, 8, 16, 20, 23, tzinfo=timezone.utc)
    assert results[1].uid == 0
    assert results[1].ut_user == "root"
    assert results[1].ut_host is None
    assert results[1].ut_tty == "tty1"
    assert results[1].source == "/var/log/lastlog"

    assert results[2].ts == datetime(2022, 12, 7, 16, 33, 30, tzinfo=timezone.utc)
    assert results[2].uid == 1000
    assert results[2].ut_user == "user"
    assert results[2].ut_host is None
    assert results[2].ut_tty == "tty1"
    assert results[2].source == "/var/log/lastlog"


def test_lastlog_sqlite(target_linux_users: Target, fs_linux: VirtualFilesystem) -> None:
    """Test if we can parse a lastlog2 SQLite3 database."""

    fs_linux.map_file("/var/lib/lastlog/lastlog2.db", absolute_path("_data/plugins/os/unix/log/lastlog/lastlog2.db"))

    target_linux_users.add_plugin(LastLogPlugin)

    records = sorted(target_linux_users.lastlog(), key=lambda r: r.ts)

    assert len(records) == 2

    assert records[0].ts == datetime(2026, 1, 28, 15, 2, 33, tzinfo=timezone.utc)
    assert records[0].uid == 0  # reverse lookup from /etc/passwd
    assert records[0].ut_user == "root"
    assert records[0].ut_host is None
    assert records[0].ut_tty == "pts/0"
    assert records[0].ut_service == "su"
    assert records[0].source == "/var/lib/lastlog/lastlog2.db"

    assert records[1].ts == datetime(2026, 2, 9, 4, 49, 13, tzinfo=timezone.utc)
    assert records[1].uid == 1000  # reverse lookup from /etc/passwd
    assert records[1].ut_user == "user"
    assert records[1].ut_host == "127.0.0.1"
    assert records[1].ut_tty == "ssh"
    assert records[1].ut_service == "sshd"
    assert records[1].source == "/var/lib/lastlog/lastlog2.db"
