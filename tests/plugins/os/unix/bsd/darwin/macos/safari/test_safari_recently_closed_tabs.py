from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.safari.safari_recently_closed_tabs import (
    SafariRecentlyClosedTabsPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "RecentlyClosedTabs.plist",
    ],
)
def test_safari_recently_closed_tabs(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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
    fs_unix.map_file(f"Users/user/Library/Safari/{test_file}", data_file)

    target_unix.add_plugin(SafariRecentlyClosedTabsPlugin)

    results = list(target_unix.safari_recently_closed_tabs())

    assert len(results) == 53

    assert results[0].closed_tab_or_window_persistent_states_version == "1"
    assert results[0].plist_path is None
    assert results[0].source == "/Users/user/Library/Safari/RecentlyClosedTabs.plist"

    assert results[1].persistent_state_type == 0
    assert results[1].plist_path == "ClosedTabOrWindowPersistentStates[0]"
    assert results[1].source == "/Users/user/Library/Safari/RecentlyClosedTabs.plist"

    assert not results[2].is_disposable
    assert results[2].ancestor_tab_uuids_key == []
    assert results[2].tab_group_type_for_tab_key
    assert results[2].tab_group_for_tab == "E3361DD6-9BEB-4FA9-A76E-ACBEFDE36107"
    assert results[2].date_closed == datetime(2026, 5, 4, 12, 15, 59, 771103, tzinfo=timezone.utc)
    assert results[2].profile_uuid == "DefaultProfile"
    assert results[2].safe_to_load
    assert results[2].tab_index == 5
    assert results[2].window_uuid == "36576C8E-921A-4E3B-999F-1E1FD0278E5E"
    assert results[2].last_visit_time == datetime(2026, 5, 4, 12, 15, 36, 419671, tzinfo=timezone.utc)
    assert results[2].tab_uuid == "147E0803-BAE8-429D-A032-A50DE3D559E2"
    assert (
        results[2].tab_url == "https://stackoverflow.com/questions/39872512/what-command-makes-a-new-file-in-terminal"
    )
    assert results[2].tab_state_version == 1
    assert results[2].tab_title == "What command makes a new file in terminal? - Stack Overflow"
    assert not results[2].is_muted
    assert results[2].process_identifier is None
    assert results[2].plist_path == "ClosedTabOrWindowPersistentStates[0]/PersistentState"
    assert results[2].source == "/Users/user/Library/Safari/RecentlyClosedTabs.plist"

    assert results[4].selected_tab_index == 0
    assert results[4].window_unified_sidebar_mode == 0
    assert not results[4].tab_bar_hidden
    assert results[4].date_closed == datetime(2026, 5, 4, 14, 11, 10, 954509, tzinfo=timezone.utc)
    assert results[4].favorites_bar_hidden
    assert not results[4].is_popup_window
    assert results[4].profile_uuid == "DefaultProfile"
    assert results[4].window_restoration_archive_data == "<NSWindowRestorationArchive>"
    assert not results[4].is_private_window
    assert not results[4].miniaturized
    assert not results[4].prefers_reading_list_sidebar_visible
    assert results[4].selected_pinned_tab_index == 9223372036854775807
    assert results[4].unnamed_tab_group_uuids == []
    assert results[4].window_content_rect == "{{87, 79}, {1264, 791}}"
    assert results[4].window_state_version == "2.0"
    assert results[4].window_uuid == "C177698D-59FA-4A93-BF08-1EB399F01B85"
    assert results[4].active_tab_group_uuid == "8B0B9E28-53F6-4C22-A0E7-4EC2DB16ECF4"
    assert results[4].plist_path == "ClosedTabOrWindowPersistentStates[1]/PersistentState"
    assert results[4].source == "/Users/user/Library/Safari/RecentlyClosedTabs.plist"
