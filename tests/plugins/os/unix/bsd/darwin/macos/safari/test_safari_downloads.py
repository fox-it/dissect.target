from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.safari.safari_downloads import SafariDownloadsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "Downloads.plist",
    ],
)
def test_safari_downloads(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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

    target_unix.add_plugin(SafariDownloadsPlugin)

    results = list(target_unix.safari_downloads())

    assert len(results) == 1

    assert results[0].download_history == []
    assert results[0].source == "/Users/user/Library/Safari/Downloads.plist"
