from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.persistence.login_items import LoginItemsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            ("BackgroundItems-v16.btm",),
            ("/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm",),
        ),
    ],
)
def test_login_items(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [user]

    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(LoginItemsPlugin)

        results = list(target_unix.login_items())
        results.sort(key=lambda r: (r.source, getattr(r, "plist_path", "")))

        assert len(results) == 4

        assert results[0].domain is None
        assert results[0].generation == 2
        assert results[0].serviceManagementLoginItemsMigrated
        assert results[0].launchServicesItemsImported
        assert results[0].backgroundAppRefreshLoadCount == 4
        assert results[0].plist_path == ("userSettingsByUserIdentifier/8122F0CD-020B-4E0C-A3AD-2FCB201C9BB0")
        assert results[0].source == "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"

        assert results[1].domain is None
        assert results[1].generation == 0
        assert not results[1].serviceManagementLoginItemsMigrated
        assert not results[1].launchServicesItemsImported
        assert results[1].backgroundAppRefreshLoadCount == 0
        assert results[1].plist_path == ("userSettingsByUserIdentifier/FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000")
        assert results[1].source == "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"

        assert results[2].domain is None
        assert results[2].generation == 1
        assert results[2].serviceManagementLoginItemsMigrated
        assert not results[2].launchServicesItemsImported
        assert results[2].backgroundAppRefreshLoadCount == 2
        assert results[2].plist_path == ("userSettingsByUserIdentifier/FFFFEEEE-DDDD-CCCC-BBBB-AAAA000000F8")
        assert results[2].source == "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"

        assert results[3].domain is None
        assert results[3].generation == 1
        assert results[3].serviceManagementLoginItemsMigrated
        assert not results[3].launchServicesItemsImported
        assert results[3].backgroundAppRefreshLoadCount == 2
        assert results[3].plist_path == ("userSettingsByUserIdentifier/FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE")
        assert results[3].source == "/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v16.btm"
