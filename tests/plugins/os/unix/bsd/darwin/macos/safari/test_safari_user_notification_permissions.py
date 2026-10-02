from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.safari.safari_user_notification_permissions import (
    SafariUserNotificationPermissionsPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "UserNotificationPermissions.plist",
    ],
)
def test_safari_user_notification_permissions(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [
        user,
    ]

    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/safari/{test_file}")
    fs_unix.map_file(f"/Users/user/Library/Safari/{test_file}", data_file)

    target_unix.add_plugin(SafariUserNotificationPermissionsPlugin)

    results = list(target_unix.safari_user_notification_permissions())

    assert len(results) == 1

    assert results[0].permission == 0
    assert results[0].date_added == datetime(2026, 5, 4, 13, 18, 13, 813088, tzinfo=timezone.utc)
    assert results[0].site == "https://www.macworld.com"
    assert results[0].source == "/Users/user/Library/Safari/UserNotificationPermissions.plist"
