from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

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
            ),
            (
                "/Users/user/Library/Preferences/loginwindow.plist",
                "/Users/user/Library/Preferences/ByHost/com.apple.loginwindow.E253F552-3A40-5010-9ACE-98662C9CFE20.plist",
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
    stat_results = []
    entries = []
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
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        stat_results.append(stat_result)
        entries.append(entry)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
        patch.object(entries[1], "stat", return_value=stat_results[1]),
    ):
        target_unix.add_plugin(LoginWindowPlugin)

        results = list(target_unix.login_window())
        results.sort(key=lambda r: r.source)

        assert len(results) == 2

        assert not results[0].MiniBuddyLaunch
        assert (
            results[0].source
            == "/Users/user/Library/Preferences/ByHost/com.apple.loginwindow.E253F552-3A40-5010-9ACE-98662C9CFE20.plist"
        )

        assert results[-1].BuildVersionStampAsNumber == 52698816
        assert results[-1].BuildVersionStampAsString == "25E246"
        assert results[-1].SystemVersionStampAsNumber == 436469760
        assert results[-1].SystemVersionStampAsString == "26.4"
        assert results[-1].source == "/Users/user/Library/Preferences/loginwindow.plist"
