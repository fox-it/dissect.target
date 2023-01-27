from datetime import datetime, timezone
from os import stat

from dissect.target.plugins.os.unix.generic import GenericPlugin

from ._utils import absolute_path

log_mtime = stat(absolute_path("data/unix/logs/empty.log")).st_mtime


def test_unix_generic_activity(target_unix, fs_unix):
    fs_unix.map_file("/var/log/some.log", absolute_path("data/unix/logs/empty.log"))
    target_unix.add_plugin(GenericPlugin)
    assert target_unix.activity == datetime.utcfromtimestamp(log_mtime).replace(tzinfo=timezone.utc)


def test_unix_generic_install_date(target_unix, fs_unix):
    fs_unix.map_file("/var/log/installer/syslog", absolute_path("data/unix/logs/empty.log"))
    target_unix.add_plugin(GenericPlugin)
    assert target_unix.install_date == datetime.utcfromtimestamp(log_mtime).replace(tzinfo=timezone.utc)
