from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.safari.safari_per_site_preferences import (
    SafariPerSitePreferencesPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "PerSitePreferences.db",
            "PerSitePreferences.db-wal",
        ]
    ],
)
def test_safari_per_site_preferences(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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
    for test_file in test_files:
        data_file = absolute_path(
            f"_data/plugins/os/unix/bsd/darwin/macos/safari/safari_per_site_preferences/{test_file}"
        )
        fs_unix.map_file(f"Users/user/Library/Safari/{test_file}", data_file)

    target_unix.add_plugin(SafariPerSitePreferencesPlugin)

    results = list(target_unix.safari_per_site_preferences())

    assert len(results) == 3

    assert results[0].table == "sqlite_sequence"
    assert results[0].name == "preference_values"
    assert results[0].seq == 2
    assert results[0].source == "/Users/user/Library/Safari/PerSitePreferences.db"

    assert results[1].table == "preference_values"
    assert results[1].id == 1
    assert results[1].preference_domain == "code.visualstudio.com"
    assert results[1].preference == "PerSitePreferencesDownloads"
    assert results[1].preference_value == 0
    assert results[1].timestamp is None
    assert results[1].sync_data is None
    assert results[1].record_name is None
    assert results[1].source == "/Users/user/Library/Safari/PerSitePreferences.db"
