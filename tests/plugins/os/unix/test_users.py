from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix._os import UnixPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_unix_passwd_file(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    passwd_file = absolute_path("_data/plugins/os/unix/_os/passwd")
    fs_unix.map_file("/etc/passwd", passwd_file)
    target_unix_users.add_plugin(UnixPlugin)

    results = list(target_unix_users.users())
    assert len(results) == 5
    assert results[0].source == "/etc/passwd"
    assert results[0].name == "root"
    assert results[0].passwd == "x"
    assert results[0].uid == 0
    assert results[0].gid == 0
    assert results[0].home == "/root"
    assert results[0].shell == "/bin/bash"


def test_unix_passwd_syslog(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    syslog_file = absolute_path("_data/plugins/os/unix/_os/passwd-syslog")
    fs_unix.map_file("/var/log/syslog", syslog_file)
    fs_unix.map_file_fh("/etc/passwd", BytesIO(b""))
    target_unix_users.add_plugin(UnixPlugin)

    results = list(target_unix_users.users(sessions=True))
    assert len(results) == 3

    # first user session of john.doe
    assert results[0].source == "/var/log/syslog"
    assert results[0].name == "john.doe"
    assert results[0].home == "/home/local/john.doe"
    assert results[0].shell == "/bin/bash"

    # second user session of john.doe with different session vars
    assert results[1].source == "/var/log/syslog"
    assert results[1].name == "john.doe"
    assert results[1].home == "/root"
    assert results[1].shell == "/bin/sh"

    # first user session of jane.doe
    assert results[2].source == "/var/log/syslog"
    assert results[2].name == "jane.doe"
    assert results[2].home == "/home/local/jane.doe"
    assert results[2].shell == "/bin/zsh"


def test_unix_passwd_backup_file(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if backup passwd files are read and only unique entries are returned."""
    passwd_file = absolute_path("_data/plugins/os/unix/_os/passwd")
    fs_unix.map_file("/etc/passwd", passwd_file)
    backup_file = passwd_file.read_bytes() + b"deleted-user:x:1001:1001:deleted-user:/home/deleted:/bin/sh"
    fs_unix.map_file_fh("/etc/passwd-", BytesIO(backup_file))
    target_unix.add_plugin(UnixPlugin)

    results = list(target_unix.users())
    assert len(results) == 5 + 1
