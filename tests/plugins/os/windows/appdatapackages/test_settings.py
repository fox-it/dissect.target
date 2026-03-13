from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import datetime as dt

from tests._utils import absolute_path

from dissect.target.plugins.os.windows.appdatapackages.settings_cache import settings_cache

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_settings_cache(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_file(
        "Users\\John\\AppData\\Local\\Packages\\Microsoft.Windows.Search_cw5n1h2txyewy\\LocalState\\DeviceSearchCache\\SettingsCache.txt",
        absolute_path("_data/plugins/os/windows/AppDataPackages/settingscache.txt"),
    )

    target_win_users.add_plugin(settings_cache)

    return target_win_users


def test_settings_cache(target_settings_cache: Target):
    results = list(target_settings_cache.settingscache())

    assert len(results) == 2
    assert results[0].ParsingName == 'examplesetting'
    assert results[0].ActivationContext == '%windir%\\system32\\rundll32.exe %windir%\\system32\\example\\setting.dll'
    assert results[0].SettingID == '{11223344-1234-ABCD-EFGH-123456789123}'
    assert results[0].Comment == 'idkwhat to write here tbh'