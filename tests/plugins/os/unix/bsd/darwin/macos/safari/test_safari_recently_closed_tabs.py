from __future__ import annotations

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

    assert results[1].PersistentStateType == 0
    assert results[1].plist_path == "ClosedTabOrWindowPersistentStates[0]"
    assert results[1].source == "/Users/user/Library/Safari/RecentlyClosedTabs.plist"

    assert not results[-1].IsDisposable
    assert results[-1].AncestorTabUUIDsKey == []
    assert results[-1].TabGroupTypeForTabKey
    assert results[-1].TabGroupForTab == "705CFB6B-1741-456B-8E58-2B213727759E"
    assert results[-1].DateClosed == "2026-05-11 08:34:41.497901"
    assert results[-1].ProfileUUID == "DefaultProfile"
    assert results[-1].SafeToLoad
    assert results[-1].TabIndex == 0
    assert results[-1].WindowUUID == "78C7D8F7-2956-4135-93F7-58A57AB07031"
    assert results[-1].LastVisitTime == "2026-05-07 12:16:08.853022"
    assert results[-1].TabUUID == "E8E9CB9D-F8DD-4AD9-8728-0691560A3DD0"
    assert (
        results[-1].TabURL
        == "https://apple.stackexchange.com/questions/475455/what-happened-to-the-periodic-scripts-on-macos-sequoia"
    )
    assert results[-1].TabStateVersion == 1
    assert results[-1].TabTitle == "What happened to the periodic scripts on macOS Sequoia? - Ask Different"
    assert results[-1].ProcessIdentifier == 626
    assert not results[-1].IsMuted
    assert results[-1].plist_path == "ClosedTabOrWindowPersistentStates[11]/PersistentState"
    assert results[-1].source == "/Users/user/Library/Safari/RecentlyClosedTabs.plist"
