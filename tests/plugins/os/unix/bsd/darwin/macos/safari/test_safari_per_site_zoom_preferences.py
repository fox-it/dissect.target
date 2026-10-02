from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.safari.safari_per_site_zoom_preferences import (
    SafariPerSiteZoomPreferencesPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "PerSiteZoomPreferences.plist",
    ],
)
def test_safari_per_site_zoom_preferences(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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

    target_unix.add_plugin(SafariPerSiteZoomPreferencesPlugin)

    results = list(target_unix.safari_per_site_zoom_preferences())

    assert len(results) == 3

    assert results[0].map_of_ck_record_names_to_ck_records == "{}"
    assert results[0].zoom_preference_version == 1
    assert results[0].source == "/Users/user/Library/Safari/PerSiteZoomPreferences.plist"

    assert results[1].site == "google.com"
    assert results[1].page_zoom_factor == 0
    assert results[1].text_zoom_factor == 1
    assert results[1].source == "/Users/user/Library/Safari/PerSiteZoomPreferences.plist"

    assert results[2].site == "apple.com"
    assert results[2].page_zoom_factor == 1
    assert results[2].text_zoom_factor == 1
    assert results[2].source == "/Users/user/Library/Safari/PerSiteZoomPreferences.plist"
