from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.remoteaccess.rustdesk import RustdeskPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_rustdesk_plugin_log(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "Windows/ServiceProfiles/LocalService/AppData/Roaming/RustDesk/log/server/TestRustdesk.log",
        absolute_path("_data/plugins/apps/remoteaccess/rustdesk/TestRustdesk.log"),
    )

    target_win_users.add_plugin(RustdeskPlugin)

    records = list(target_win_users.rustdesk.logs())
    assert len(records) == 1

    assert records[0].ts == datetime(2025, 1, 1, 13, 4, 8, 350802, tzinfo=timezone.utc)
    assert records[0].message == "DEBUG src\\server\\connection.rs:983 #1362 Connection opened from REDACTED IP:6074."
    assert (
        records[0].source
        == "sysvol/Windows/ServiceProfiles/LocalService/AppData/Roaming/RustDesk/log/server/TestRustdesk.log"
    )
    assert records[0].username is None
    assert records[0].user_id is None
    assert records[0].user_home is None


def test_rustdesk_plugin_user_log(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "Users/John/AppData/Roaming/Rustdesk/log/TestRustdesk.log",
        absolute_path("_data/plugins/apps/remoteaccess/rustdesk/TestRustdesk.log"),
    )

    target_win_users.add_plugin(RustdeskPlugin)

    records = list(target_win_users.rustdesk.logs())
    assert len(records) == 1
    assert records[0].ts == datetime(2025, 1, 1, 13, 4, 8, 350802, tzinfo=timezone.utc)
    assert records[0].message == "DEBUG src\\server\\connection.rs:983 #1362 Connection opened from REDACTED IP:6074."
    assert records[0].source == "C:/Users/John/AppData/Roaming/Rustdesk/log/TestRustdesk.log"
