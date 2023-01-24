from datetime import datetime, timezone
from os import stat

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.log.auth import AuthLogRecord, AuthPlugin

from ._utils import absolute_path

# NOTE: stat info of files will be different depending
# on when the project was cloned by git. That's why we
# derive the st_ctime of all test data files using os.stat.


def test_auth_plugin(target_unix, fs_unix: VirtualFilesystem):
    data_path = "data/unix/logs/auth/auth.log"
    data_file = absolute_path(data_path)
    fs_unix.map_file("var/log/auth.log", data_file)

    year = datetime.fromtimestamp(stat(absolute_path(data_path)).st_ctime).year

    target_unix.add_plugin(AuthPlugin)
    results = list(target_unix.authlog())

    assert len(results) == 10
    assert isinstance(results[0], type(AuthLogRecord()))
    assert results[0].ts == datetime(year, 11, 14, 6, 39, 1, tzinfo=timezone.utc)
    assert results[0].message == "CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_plugin_with_gz(target_unix, fs_unix: VirtualFilesystem):
    empty_file = absolute_path("data/empty.log")
    fs_unix.map_file("var/log/auth.log", empty_file)

    gz_path = "data/unix/logs/auth/auth.log.gz"
    gz_file = absolute_path(gz_path)
    fs_unix.map_file("var/log/auth.log.gz", gz_file)

    year = datetime.fromtimestamp(stat(absolute_path(gz_path)).st_ctime).year

    target_unix.add_plugin(AuthPlugin)
    results = list(target_unix.authlog())

    assert len(results) == 10
    assert isinstance(results[0], type(AuthLogRecord()))
    assert results[0].ts == datetime(year, 11, 14, 6, 39, 1, tzinfo=timezone.utc)
    assert results[0].message == "CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_plugin_with_bz(target_unix, fs_unix: VirtualFilesystem):
    empty_file = absolute_path("data/empty.log")
    fs_unix.map_file("var/log/auth.log", empty_file)

    bz_path = "data/unix/logs/auth/auth.log.bz2"
    bz_file = absolute_path(bz_path)
    fs_unix.map_file("var/log/auth.log.1.bz2", bz_file)

    year = datetime.fromtimestamp(stat(absolute_path(bz_path)).st_ctime).year

    target_unix.add_plugin(AuthPlugin)
    results = list(target_unix.authlog())

    assert len(results) == 10
    assert isinstance(results[0], type(AuthLogRecord()))
    assert results[0].ts == datetime(year, 11, 14, 6, 39, 1, tzinfo=timezone.utc)
    assert results[0].message == "CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)"


def test_auth_plugin_year_rollover(target_unix, fs_unix: VirtualFilesystem):
    data_path = "data/unix/logs/auth/secure"
    data_file = absolute_path(data_path)
    fs_unix.map_file("var/log/secure", data_file)

    year = datetime.fromtimestamp(stat(absolute_path(data_path)).st_ctime).year

    target_unix.add_plugin(AuthPlugin)
    results = list(target_unix.authlog())

    assert len(results) == 2
    assert isinstance(results[0], type(AuthLogRecord()))
    assert isinstance(results[1], type(AuthLogRecord()))
    assert results[0].ts == datetime(year, 12, 31, 3, 14, 0, tzinfo=timezone.utc)
    assert results[1].ts == datetime(year + 1, 1, 1, 13, 37, 0, tzinfo=timezone.utc)
