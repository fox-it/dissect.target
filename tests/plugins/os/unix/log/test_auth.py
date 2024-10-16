from datetime import datetime, timezone
from io import BytesIO
from unittest.mock import patch
from zoneinfo import ZoneInfo

from flow.record.fieldtypes import datetime as dt

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.log.auth import AuthPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_auth_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO("Europe/Amsterdam".encode()))

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
        assert isinstance(results[0], type(AuthLogRecord()))
        assert results[-1].ts == dt(2022, 11, 14, 6, 39, 1, tzinfo=ZoneInfo("Europe/Amsterdam"))
        assert results[-1].message == "CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_plugin_with_gz(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO("Pacific/Honolulu".encode()))

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
        assert isinstance(results[0], type(AuthLogRecord()))
        assert results[-1].ts == dt(2022, 11, 14, 6, 39, 1, tzinfo=ZoneInfo("Pacific/Honolulu"))
        assert results[-1].message == "CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_plugin_with_bz(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO("America/Nuuk".encode()))

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
        assert isinstance(results[0], type(AuthLogRecord()))
        assert results[-1].ts == dt(2022, 11, 14, 6, 39, 1, tzinfo=ZoneInfo("America/Nuuk"))
        assert results[-1].message == "CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_plugin_year_rollover(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/timezone", BytesIO("Etc/UTC".encode()))

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
        assert isinstance(results[0], type(AuthLogRecord()))
        assert isinstance(results[1], type(AuthLogRecord()))
        assert results[0].ts == dt(2021, 12, 31, 3, 14, 0, tzinfo=ZoneInfo("Etc/UTC"))
        assert results[1].ts == dt(2022, 1, 1, 13, 37, 0, tzinfo=ZoneInfo("Etc/UTC"))


def test_auth_plugin_iso_date_format(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """test if we correctly handle Ubuntu 24.04 ISO formatted dates."""

    fs_unix.map_file("/var/log/auth.log", absolute_path("_data/plugins/os/unix/log/auth/iso.log"))
    target_unix.add_plugin(AuthPlugin)

    results = sorted(list(target_unix.authlog()), key=lambda r: r.ts)
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
