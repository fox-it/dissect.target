from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.os.unix.log.auth import AuthPlugin
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import VirtualFilesystem


def test_auth(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))

    data_path = "_data/plugins/os/unix/log/auth/auth.log"
    data_file = absolute_path(data_path)
    fs_unix.map_file("var/log/auth.log", data_file)

    entry = fs_unix.get("var/log/auth.log")
    stat = entry.stat()
    stat.st_mtime = datetime(2022, 6, 1, tzinfo=timezone.utc).timestamp()

    with patch.object(entry, "stat", return_value=stat):
        target_unix.add_plugin(AuthPlugin)
        results = list(target_unix.authlog())

        assert len(results) == 10
        assert results[-1].ts == dt(2022, 11, 14, 6, 39, 1, tzinfo=ZoneInfo("Europe/Amsterdam"))
        assert results[-1].message == "pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_with_gz(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Pacific/Honolulu"))

    empty_file = absolute_path("_data/plugins/os/unix/log/empty.log")
    fs_unix.map_file("var/log/auth.log", empty_file)

    gz_path = "_data/plugins/os/unix/log/auth/auth.log.gz"
    gz_file = absolute_path(gz_path)
    fs_unix.map_file("var/log/auth.log.gz", gz_file)

    entry = fs_unix.get("var/log/auth.log.gz")
    stat = entry.stat()
    stat.st_mtime = datetime(2022, 6, 1, tzinfo=timezone.utc).timestamp()

    with patch.object(entry, "stat", return_value=stat):
        target_unix.add_plugin(AuthPlugin)
        results = list(target_unix.authlog())

        assert len(results) == 10
        assert results[-1].ts == dt(2022, 11, 14, 6, 39, 1, tzinfo=ZoneInfo("Pacific/Honolulu"))
        assert results[-1].message == "pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_with_bz(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"America/Nuuk"))

    empty_file = absolute_path("_data/plugins/os/unix/log/empty.log")
    fs_unix.map_file("var/log/auth.log", empty_file)

    bz_path = "_data/plugins/os/unix/log/auth/auth.log.bz2"
    bz_file = absolute_path(bz_path)
    fs_unix.map_file("var/log/auth.log.1.bz2", bz_file)

    entry = fs_unix.get("var/log/auth.log.1.bz2")
    stat = entry.stat()
    stat.st_mtime = datetime(2022, 6, 1, tzinfo=timezone.utc).timestamp()

    with patch.object(entry, "stat", return_value=stat):
        target_unix.add_plugin(AuthPlugin)
        results = list(target_unix.authlog())

        assert len(results) == 10
        assert results[-1].ts == dt(2022, 11, 14, 6, 39, 1, tzinfo=ZoneInfo("America/Nuuk"))
        assert results[-1].message == "pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_year_rollover(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Etc/UTC"))

    data_path = "_data/plugins/os/unix/log/auth/secure"
    data_file = absolute_path(data_path)
    fs_unix.map_file("var/log/secure", data_file)

    entry = fs_unix.get("var/log/secure")
    stat = entry.stat()
    stat.st_mtime = datetime(2022, 6, 1, tzinfo=timezone.utc).timestamp()

    with patch.object(entry, "stat", return_value=stat):
        target_unix.add_plugin(AuthPlugin)
        results = list(target_unix.authlog())

        assert len(results) == 2
        results.reverse()
        assert results[0].ts == dt(2021, 12, 31, 3, 14, 0, tzinfo=ZoneInfo("Etc/UTC"))
        assert results[1].ts == dt(2022, 1, 1, 13, 37, 0, tzinfo=ZoneInfo("Etc/UTC"))


@pytest.mark.parametrize(
    ("message", "results"),
    [
        pytest.param(
            "Mar 29 10:43:01 ubuntu-1 sshd[1193]: Accepted password for test_user from 8.8.8.8 port 52942 ssh2",
            {
                "service": "sshd",
                "pid": 1193,
                "action": "accepted authentication",
                "authentication_type": "password",
                "user": "test_user",
                "remote_ip": "8.8.8.8",
                "port": 52942,
            },
            id="sshd: accepted password",
        ),
        pytest.param(
            "Jun 4 22:14:15 ubuntu-1 sshd[41458]: Failed password for root from 8.8.8.8 port 22 ssh2",
            {
                "service": "sshd",
                "pid": 41458,
                "action": "failed authentication",
                "authentication_type": "password",
                "user": "root",
                "remote_ip": "8.8.8.8",
                "port": 22,
            },
            id="sshd: failed password",
        ),
        pytest.param(
            "Jun 4 22:14:15 ubuntu-1 sshd[12345]: reverse mapping checking getaddrinfo for some-hostname-with-digits-012.34.56.78.example.com [90.12.34.56] failed - POSSIBLE BREAK-IN ATTEMPT!",  # noqa: E501
            {
                "service": "sshd",
                "pid": 12345,
                "remote_ips": ["90.12.34.56", "12.34.56.78"],
            },
            id="sshd: reverse dns ip addr",
        ),
        pytest.param(
            "Mar 27 13:08:09 ubuntu-1 sshd[1361]: Accepted publickey for test_user "
            "from 8.8.8.8 port 12345 ssh2: RSA SHA256:123456789asdfghjklertzuio",
            {
                "service": "sshd",
                "pid": 1361,
                "action": "accepted authentication",
                "authentication_type": "publickey",
                "user": "test_user",
                "remote_ip": "8.8.8.8",
                "port": 12345,
                "ssh_protocol": "ssh2",
                "encryption_algorithm": "RSA",
                "hash_algorithm": "SHA256",
                "key_hash": "123456789asdfghjklertzuio",
            },
            id="sshd: accepted publickey",
        ),
        pytest.param(
            "Mar 27 13:08:09 ubuntu-1 sshd[1361]: Failed publickey for test_user from 8.8.8.8 port 12345 ssh2.",
            {
                "service": "sshd",
                "pid": 1361,
                "action": "failed authentication",
                "authentication_type": "publickey",
                "user": "test_user",
                "remote_ip": "8.8.8.8",
                "port": 12345,
            },
            id="sshd: failed publickey",
        ),
        pytest.param(
            "Mar 27 13:06:56 ubuntu-1 sshd[1291]: Server listening on 127.0.0.1 port 22.",
            {
                "service": "sshd",
                "pid": 1291,
                "host_ip": "127.0.0.1",
                "port": 22,
            },
            id="sshd: listening",
        ),
        pytest.param(
            "Mar 27 13:08:09 ubuntu-1 sshd[1361]: pam_unix(sshd:session): session opened for user test_user by (uid=0)",
            {
                "service": "sshd",
                "pid": 1361,
                "action": "session opened",
                "user": "test_user",
                "user_uid": None,
                "by_uid": 0,
            },
            id="sshd: pam_unix",
        ),
        pytest.param(
            "Mar 27 13:08:09 ubuntu-1 sshd[1361]: pam_unix(sshd:session): session opened "
            "for user root(uid=0) by (uid=0)",
            {
                "service": "sshd",
                "pid": 1361,
                "action": "session opened",
                "user": "root",
                "user_uid": 0,
                "by_uid": 0,
            },
            id="sshd: pam_unix",
        ),
        pytest.param(
            "Mar 27 13:06:56 ubuntu-1 systemd-logind[1118]: Watching system buttons "
            "on /dev/input/event0 (Power Button)",
            {
                "service": "systemd-logind",
                "pid": 1118,
                "action": "Watching system buttons",
                "device": "/dev/input/event0",
                "device_name": "Power Button",
            },
            id="systemd-logind: watching system buttons",
        ),
        pytest.param(
            "Mar 27 13:06:56 ubuntu-1 systemd-logind[1118]: New seat seat0.",
            {
                "service": "systemd-logind",
                "pid": 1118,
                "action": "new seat",
                "seat": "seat0",
            },
            id="systemd-logind: new seat",
        ),
        pytest.param(
            "Mar 27 13:10:08 ubuntu-1 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/test_user ; "
            "USER=root ; COMMAND=/usr/bin/apt-key add -",
            {
                "service": "sudo",
                "pid": None,
                "tty": "pts/0",
                "pwd": "/home/test_user",
                "effective_user": "root",
                "command": "/usr/bin/apt-key add -",
            },
            id="sudo: command",
        ),
        pytest.param(
            "Apr  3 12:32:23 ubuntu-1 su[1521]: Successful su for user by root",
            {"service": "su", "pid": 1521, "su_result": "success", "user": "user", "by": "root"},
            id="su: success",
        ),
        pytest.param(
            "Apr  3 12:32:23 ubuntu-1 su[1531]: 'su root' failed for user by root",
            {
                "service": "su",
                "pid": 1531,
                "su_result": "failed",
                "command": "su root",
                "user": "user",
                "by": "root",
            },
            id="su: failed",
        ),
        pytest.param(
            "Apr  3 12:32:23 ubuntu-1 pkexec[1531]: user: Executing command [USER=root] "
            "[TTY=unknown] [CWD=/home/user] [COMMAND=/usr/lib/update-notifier/package-system-locked]",
            {
                "service": "pkexec",
                "pid": 1531,
                "action": "executing command",
                "user": "user",
                "effective_user": "root",
                "tty": "unknown",
                "cwd": "/home/user",
                "command": "/usr/lib/update-notifier/package-system-locked",
            },
            id="pkexec: executing command",
        ),
        pytest.param(
            "Mar 27 13:17:01 ubuntu-1 CRON[2623]: pam_unix(cron:session): session closed for user root",
            {
                "service": "CRON",
                "pid": 2623,
                "action": "session closed",
                "user": "root",
            },
            id="cron: pam_unix",
        ),
    ],
)
def test_auth_additional_fields(
    target_unix: Target, fs_unix: VirtualFilesystem, tmp_path: Path, message: str, results: dict[str, str | int]
) -> None:
    data_path = tmp_path / "auth.log"
    data_path.write_text(message)
    fs_unix.map_file("var/log/auth.log", data_path)

    target_unix.add_plugin(AuthPlugin)

    result = list(target_unix.authlog())
    assert len(result) == 1

    for key, value in results.items():
        plugin_result = getattr(result[0], key)
        if isinstance(value, list):
            value = sorted(map(str, value))
            plugin_result = sorted(map(str, plugin_result))

        assert plugin_result == value


def test_auth_iso_date_format(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we correctly handle Ubuntu 24.04 ISO formatted dates."""

    fs_unix.map_file("/var/log/auth.log", absolute_path("_data/plugins/os/unix/log/auth/iso.log"))
    target_unix.add_plugin(AuthPlugin)

    results = sorted(target_unix.authlog(), key=lambda r: r.ts)
    assert len(results) == 10

    assert results[0].ts == datetime(2024, 12, 31, 11, 37, 1, 123456, tzinfo=timezone.utc)
    assert results[0].service == "sudo"
    assert results[0].pid is None
    assert results[0].tty == "pts/0"
    assert results[0].pwd == "/home/user"
    assert results[0].effective_user == "root"
    assert results[0].command == "/usr/bin/chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg"
    assert results[0].source == "/var/log/auth.log"
    assert (
        results[0].message
        == "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg"  # noqa: E501
    )


def test_auth_direct_mode() -> None:
    data_path = absolute_path("_data/plugins/os/unix/log/auth/auth.log")

    target = Target.open_direct([data_path])
    results = list(target.authlog())

    assert len(results) == 10
