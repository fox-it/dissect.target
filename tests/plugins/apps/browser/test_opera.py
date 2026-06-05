from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target.plugins.apps.browser.opera import OperaPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_opera_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_dir(
        "Users\\John\\AppData\\Roaming\\Opera Software\\Opera Stable\\Default\\",
        absolute_path("_data/plugins/apps/browser/opera/"),
    )
    fs_win.map_dir(
        (
            "Users\\John\\AppData\\Roaming\\Opera Software\\Opera Stable"
            "\\_side_profiles\\31303232385F31323239343834393136\\Default"
        ),
        absolute_path("_data/plugins/apps/browser/opera/"),
    )

    target_win_users.add_plugin(OperaPlugin)
    return target_win_users


@pytest.fixture
def target_operagx_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_dir(
        "Users\\John\\AppData\\Roaming\\Opera Software\\Opera GX Stable\\Default\\",
        absolute_path("_data/plugins/apps/browser/opera/"),
    )
    fs_win.map_dir(
        (
            "Users\\John\\AppData\\Roaming\\Opera Software\\Opera GX Stable"
            "\\_side_profiles\\31303232385F31323239343834393136\\Default\\"
        ),
        absolute_path("_data/plugins/apps/browser/opera/"),
    )

    target_win_users.add_plugin(OperaPlugin)
    return target_win_users


@pytest.mark.parametrize(
    "target_platform",
    ["target_opera_win", "target_operagx_win"],
)
def test_opera_history(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.opera.history())

    assert len(records) == 164
    assert {"opera"} == {record.browser for record in records}

    assert records[75].url == "https://github.com/fox-it/dissect.target"
    assert records[75].id == 76
    assert records[75].visit_count == 2
    assert records[75].ts == dt("2026-03-17 13:24:54.736168+00:00")


@pytest.mark.parametrize(
    "target_platform",
    ["target_opera_win", "target_operagx_win"],
)
def test_opera_cookies(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.opera.cookies())

    assert len(records) == 102
    assert {"opera"} == {record.browser for record in records}

    assert records[-1].host == ".github.com"
    assert records[-1].name == "tz"


@pytest.mark.parametrize(
    "target_platform",
    ["target_opera_win", "target_operagx_win"],
)
def test_opera_downloads(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.opera.downloads())

    assert len(records) == 2
    assert {"opera"} == {record.browser for record in records}

    assert records[0].url == "https://codeload.github.com/fox-it/dissect.target/zip/refs/tags/3.25.1"
    assert records[0].tab_url == "https://github.com/fox-it/dissect.target/releases/tag/3.25.1"
    assert records[0].state == "complete"
    assert records[0].mime_type == "application/x-zip-compressed"
    assert records[0].path == "C:\\Users\\User\\Downloads\\dissect.target-3.25.1.zip"


@pytest.mark.parametrize(
    "target_platform",
    ["target_opera_win", "target_operagx_win"],
)
def test_opera_extensions(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.opera.extensions())

    assert len(records) == 66
    assert {"opera"} == {record.browser for record in records}

    assert records[0].name == "Web Store"
    assert not records[0].blacklisted
    assert records[0].extension_id == "ahfgeienlihckogmohjhadlkjgocpleb"
    assert records[0].description == "Discover great apps, games, extensions and themes for Opera."
    assert records[0].version == "0.2"

    assert records[65].name == "NewTab. Search"
    assert records[65].blacklisted
    assert records[65].extension_id == "pookachmhghnpgjhebhilcidgdphdlhi"
    assert records[65].description == "The extension changes default search provider."
    assert records[65].version == "2.0.0.0"
