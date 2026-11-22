from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.safari.safari_favicons import SafariFaviconsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "favicons.db",
            "favicons.db-wal",
        ]
    ],
)
def test_safari_favicons(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/safari/safari_favicons/{test_file}")
        fs_unix.map_file(f"Users/user/Library/Safari/Favicon Cache/{test_file}", data_file)

    target_unix.add_plugin(SafariFaviconsPlugin)

    results = list(target_unix.safari_favicons())

    assert len(results) == 142

    assert results[0].table == "page_url"
    assert (
        results[0].url
        == "https://www.google.com/search?client=safari&rls=en&q=digital+forensic+artifacts+repositroy&ie=UTF-8&oe=UTF-8&sei=jYX4abCaDamK9u8PoYyHyAU"
    )
    assert results[0].uuid == "7273D3EF-09B6-498C-8385-47AEFBA2E3F0"
    assert results[0].source == "/Users/user/Library/Safari/Favicon Cache/favicons.db"

    assert results[113].table == "icon_info"
    assert results[113].uuid == "7273D3EF-09B6-498C-8385-47AEFBA2E3F0"
    assert results[113].url == "https://www.gstatic.com/images/branding/searchlogo/ico/favicon.ico"
    assert results[113].timestamp == datetime(2026, 5, 4, 11, 39, 58, 200725, tzinfo=timezone.utc)
    assert results[113].width == 32
    assert results[113].height == 32
    assert results[113].has_generated_representations
    assert results[113].source == "/Users/user/Library/Safari/Favicon Cache/favicons.db"

    assert results[137].table == "rejected_resources"
    assert (
        results[137].page_url
        == "https://www.google.com/search?client=safari&rls=en&q=digital+forensic+artifacts+repositroy&ie=UTF-8&oe=UTF-8"
    )
    assert results[137].icon_url == "https://www.google.com/favicon.ico"
    assert results[137].source == "/Users/user/Library/Safari/Favicon Cache/favicons.db"
