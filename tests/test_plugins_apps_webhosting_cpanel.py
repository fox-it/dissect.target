from datetime import datetime, timezone

from dissect.target.plugins.apps.webhosting.cpanel import CpanelPlugin

from ._utils import absolute_path


def test_cpanel_plugin(target_unix, fs_unix):
    data_file = absolute_path("data/plugins/apps/webhosting/cpanel/lastlogin")
    fs_unix.map_file("/home/test/.lastlogin", data_file)

    fs_unix.makedirs("/usr/local/cpanel/logs")

    passwd_file = absolute_path("data/unix/configs/passwd")
    fs_unix.map_file("/etc/passwd", passwd_file)

    target_unix.add_plugin(CpanelPlugin)

    results = list(target_unix.cpanel.lastlogin())

    record = results[0]

    assert len(results) == 4
    assert record.ts == datetime(2023, 6, 27, 13, 22, 13, tzinfo=timezone.utc)
    assert record.user == "test"
    assert record.remote_ip == "8.8.8.8"
