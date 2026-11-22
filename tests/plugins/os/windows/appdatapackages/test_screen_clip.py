from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import datetime as dt

from tests._utils import absolute_path

from dissect.target.plugins.os.windows.appdatapackages.screenclip import screenclip, WindowsScreenClipJsonRecord, WindowsScreenClipPngRecord

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_screenclip(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Packages\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TempState\\ScreenClip",
        absolute_path("_data/plugins/os/windows/AppDataPackages/screenclips"),
    )

    target_win_users.add_plugin(screenclip)

    return target_win_users


def test_settings_cache(target_screenclip: Target):
    results = list(target_screenclip.screenclip())
    png_records = [record for record in results if isinstance(record, type(WindowsScreenClipPngRecord()))]
    json_records = [record for record in results if isinstance(record, type(WindowsScreenClipJsonRecord()))]



    assert len(png_records) == 2
    assert len(json_records) == 2


    assert json_records[0].appDisplayName == "Firefox"
    assert json_records[0].activationUrl == "ms-shellactivity:"
    assert json_records[0].username == "John"
    assert json_records[0].visualElements == "{'backgroundColor': 'black', 'displayText': 'Firefox'}"
    print(png_records[0])
    assert png_records[0].sha256Hash == "ccf1f6398826aa716c90797aea202bc654166575c7f9a76303d10c6da838bdad"
    assert png_records[0].sha1Hash == "a166b3cb39cea116b8611a1533c3fcc6a8f2676b"
    assert png_records[0].md5Hash == "7acaf36dde2f286c8da2f84e36a090ad"


