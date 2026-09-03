from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.login_window import LoginWindowPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "loginwindow.plist",
                "com.apple.loginwindow.E253F552-3A40-5010-9ACE-98662C9CFE20.plist",
                "com.apple.loginwindow.16130786-970B-53D1-A07B-005E50471D95.plist",
            ),
            (
                "/Users/user/Library/Preferences/loginwindow.plist",
                "/Users/user/Library/Preferences/ByHost/com.apple.loginwindow.E253F552-3A40-5010-9ACE-98662C9CFE20.plist",
                "/Users/user/Library/Preferences/ByHost/com.apple.loginwindow.16130786-970B-53D1-A07B-005E50471D95.plist",
            ),
        ),
    ],
)
def test_login_window(
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
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/login_window/{name}")
        fs_unix.map_file(path, data_file)

    target_unix.add_plugin(LoginWindowPlugin)

    results = list(target_unix.login_window())
    results.sort(key=lambda r: r.source)

    assert len(results) == 5

    assert not results[0].hide
    assert results[0].bundle_id == "com.apple.finder"
    assert results[0].path == "/System/Library/CoreServices/Finder.app"
    assert results[0].background_state == 2
    assert results[0].plist_path == "TALAppsToRelaunchAtLogin[0]"
    assert (
        results[0].source
        == "/Users/user/Library/Preferences/ByHost/com.apple.loginwindow.16130786-970B-53D1-A07B-005E50471D95.plist"
    )

    assert not results[3].mini_buddy_launch
    assert (
        results[3].source
        == "/Users/user/Library/Preferences/ByHost/com.apple.loginwindow.E253F552-3A40-5010-9ACE-98662C9CFE20.plist"
    )

    assert results[4].build_version_as_string == "25E246"
    assert results[4].build_version_stamp_as_number == 52698816
    assert results[4].system_version_stamp_as_string == "26.4"
    assert results[4].system_version_stamp_as_number == 436469760
    assert results[4].source == "/Users/user/Library/Preferences/loginwindow.plist"
