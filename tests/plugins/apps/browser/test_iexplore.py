from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import path

from dissect.target.plugins.apps.browser import iexplore
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target

# NOTE: Missing cookies, extensions and passwords tests.


@pytest.fixture
def target_iexplore(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    base_path = "Users\\John\\AppData\\Local\\Microsoft\\Windows\\WebCache"
    files = [
        ("WebCacheV01.dat", "_data/plugins/apps/browser/iexplore/WebCacheV01.dat.gz", "gzip"),
    ]

    for filename, test_path, compression in files:
        fs_win.map_file(f"{base_path}\\{filename}", absolute_path(test_path), compression=compression)

    target_win_users.add_plugin(iexplore.InternetExplorerPlugin)

    return target_win_users


def test_iexplore_history(target_iexplore: Target) -> None:
    records = list(target_iexplore.iexplore.history())
    assert len(records) == 41

    # Test namespaced plugin
    records = list(target_iexplore.browser.history())
    assert len(records) == 41


def test_iexplore_downloads(target_iexplore: Target) -> None:
    records = list(target_iexplore.iexplore.downloads())
    assert len(records) == 1
    assert records[0].path == path.from_windows("C:\\Users\\John\\Downloads\\archlinux-2023.02.01-x86_64.iso")
    assert records[0].url == "https://mirror.cj2.nl/archlinux/iso/2023.02.01/archlinux-2023.02.01-x86_64.iso"
