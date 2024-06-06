from typing import Iterator

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser.edge import EdgePlugin
from tests._utils import absolute_path

# NOTE: Missing cookie tests for Edge.


@pytest.fixture
def target_edge_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\",
        absolute_path("_data/plugins/apps/browser/edge/"),
    )

    target_win_users.add_plugin(EdgePlugin)

    yield target_win_users


@pytest.fixture
def target_edge_unix(target_unix_users, fs_unix):
    fs_unix.map_dir("/root/.config/microsoft-edge/Default/", absolute_path("_data/plugins/apps/browser/edge/"))
    target_unix_users.add_plugin(EdgePlugin)

    yield target_unix_users


@pytest.mark.parametrize(
    "target_platform",
    ["target_edge_win", "target_edge_unix"],
)
def test_edge_history(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.edge.history())

    assert len(records) == 45
    assert set(["edge"]) == set(record.browser for record in records)

    assert records[-1].url == "https://github.com/fox-it/dissect"
    assert records[-1].id == "45"
    assert records[-1].visit_count == 2
    assert records[-1].ts == dt("2023-02-24T11:54:44.875477+00:00")


@pytest.mark.parametrize(
    "target_platform",
    ["target_edge_win", "target_edge_unix"],
)
def test_edge_downloads(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.edge.downloads())

    assert len(records) == 2
    assert set(["edge"]) == set(record.browser for record in records)

    assert records[0].id == 1
    assert records[0].ts_start == dt("2023-02-24T11:52:36.631304+00:00")
    assert records[0].ts_end == dt("2023-02-24T11:52:37.068768+00:00")
    assert records[0].url == "https://codeload.github.com/fox-it/dissect/zip/refs/heads/main"


@pytest.mark.parametrize(
    "target_platform",
    ["target_edge_win", "target_edge_unix"],
)
def test_edge_extensions(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.edge.extensions())

    assert len(records) == 39
    assert set(["edge"]) == set(record.browser for record in records)

    assert records[0].ts_install == dt("2023-04-18T08:39:57.968208+00:00")
    assert records[0].ts_update == dt("2023-04-18T08:39:57.968208+00:00")
    assert records[0].name == "Web Store"
    assert records[0].version == "0.2"
    assert records[0].id == "ahfgeienlihckogmohjhadlkjgocpleb"


def test_windows_edge_passwords_plugin(target_edge_win: Target) -> None:
    records = list(target_edge_win.edge.passwords())

    assert len(records) == 2

    for record in records:
        assert record.browser == "edge"
        assert record.decrypted_username == "username"
        assert record.decrypted_password is None

    assert records[0].url == "https://example.com/"
    assert records[1].url == "https://example.org/"


def test_unix_edge_passwords_basic_plugin(target_edge_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file(
        "/root/.config/microsoft-edge/Default/Login Data",
        absolute_path("_data/plugins/apps/browser/chromium/unix/basic/Login Data"),
    )

    records = list(target_edge_unix.edge.passwords())

    assert len(records) == 2

    for record in records:
        assert record.browser == "edge"
        assert record.decrypted_username == "username"
        assert record.decrypted_password == "password"

    assert records[0].url == "https://example.com/"
    assert records[1].url == "https://example.org/"


def test_unix_edge_passwords_gnome_plugin(target_edge_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file(
        "/root/.config/microsoft-edge/Default/Login Data",
        absolute_path("_data/plugins/apps/browser/chromium/unix/gnome/Login Data"),
    )

    records = list(target_edge_unix.edge.passwords())

    assert len(records) == 1

    assert records[0].decrypted_username == "username"
    assert records[0].decrypted_password is None
    assert records[0].url == "https://test.com/"
