from datetime import datetime, timezone

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.webhosting.cpanel import CPanelPlugin
from tests._utils import absolute_path


def test_cpanel_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/apps/webhosting/cpanel/lastlogin")
    fs_unix.map_file("/home/user/.lastlogin", data_file)

    fs_unix.makedirs("/usr/local/cpanel/logs")

    target_unix_users.add_plugin(CPanelPlugin)

    results = list(target_unix_users.cpanel.lastlogin())

    record = results[0]

    assert len(results) == 6
    assert record.ts == datetime(2023, 6, 27, 13, 22, 13, tzinfo=timezone.utc)
    assert record.user == "user"
    assert record.remote_ip == "8.8.8.8"
