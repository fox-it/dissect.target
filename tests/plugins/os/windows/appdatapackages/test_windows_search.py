from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import datetime as dt

from tests._utils import absolute_path

from dissect.target.plugins.os.windows.AppDataPackages.windows_search import app_cache

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_app_cache(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_file(
        "Users\\John\\AppData\\Local\\Packages\\Microsoft.Windows.Search_cw5n1h2txyewy\\LocalState\\DeviceSearchCache\\AppCache134176063414577965.txt",
        absolute_path("_data/plugins/os/windows/AppDataPackages/AppCache123123123.txt"),
    )

    target_win_users.add_plugin(app_cache)

    return target_win_users


def test_settings_cache(target_app_cache: Target):
    results = list(target_app_cache.appcache())

    assert len(results) == 2
    print(results[0])
    assert results[0].ParsingName == 'Z8X7C6V5B4N3M2L1'
    assert results[0].FileExtension == '.qwe'
    assert results[0].FileName == 'random_tool'
    assert results[0].PackageFullName == 'com.random.tool'