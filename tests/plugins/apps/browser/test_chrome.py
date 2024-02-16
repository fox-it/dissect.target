from typing import Iterator

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser.chrome import ChromePlugin
from tests._utils import absolute_path

# NOTE: Missing cookie tests for Chrome.


@pytest.fixture
def target_chrome_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\",
        absolute_path("_data/plugins/apps/browser/chrome/"),
    )

    target_win_users.add_plugin(ChromePlugin)

    yield target_win_users


@pytest.fixture
def target_chrome_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Iterator[Target]:
    fs_unix.map_dir("/root/.config/google-chrome/Default/", absolute_path("_data/plugins/apps/browser/chrome/"))

    target_unix_users.add_plugin(ChromePlugin)

    yield target_unix_users


@pytest.mark.parametrize(
    "target_platform",
    ["target_chrome_win", "target_chrome_unix"],
)
def test_chrome_history(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.chrome.history())

    assert len(records) == 5
    assert set(["chrome"]) == set(record.browser for record in records)

    assert (
        records[0].url == "https://www.google.com/search?q=github+fox-it+dissect&oq=github+fox-it+dissect"
        "&aqs=chrome..69i57.12832j0j4&sourceid=chrome&ie=UTF-8"
    )
    assert records[0].id == "1"
    assert records[0].visit_count == 2
    assert records[0].ts == dt("2023-02-24T11:54:07.157810+00:00")


@pytest.mark.parametrize(
    "target_platform",
    ["target_chrome_win", "target_chrome_unix"],
)
def test_chrome_downloads(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.chrome.downloads())

    assert len(records) == 1
    assert set(["chrome"]) == set(record.browser for record in records)

    assert records[0].id == 6
    assert records[0].ts_start == dt("2023-02-24T11:54:19.726147+00:00")
    assert records[0].ts_end == dt("2023-02-24T11:54:21.030043+00:00")
    assert records[0].url == "https://codeload.github.com/fox-it/dissect/zip/refs/heads/main"


@pytest.mark.parametrize(
    "target_platform",
    ["target_chrome_win", "target_chrome_unix"],
)
def test_chrome_extensions(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.chrome.extensions())

    assert len(records) == 8
    assert set(["chrome"]) == set(record.browser for record in records)

    assert records[0].ts_install == dt("2022-11-24T15:20:43.682152+00:00")
    assert records[0].ts_update == dt("2022-11-24T15:20:43.682152+00:00")
    assert records[0].name == "Web Store"
    assert records[0].version == "0.2"
    assert records[0].id == "ahfgeienlihckogmohjhadlkjgocpleb"


def test_windows_chrome_passwords_plugin(target_chrome_win: Target) -> None:
    records = list(target_chrome_win.chrome.passwords())

    assert len(records) == 2

    for record in records:
        assert record.browser == "chrome"
        assert record.decrypted_username == "username"
        assert record.decrypted_password == ""

    assert records[0].url == "https://example.com/"
    assert records[1].url == "https://example.org/"


def test_unix_chrome_passwords_basic_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_dir(
        "/root/.config/google-chrome/Default/", absolute_path("_data/plugins/apps/browser/chromium/unix/basic/")
    )
    target_unix_users.add_plugin(ChromePlugin)

    records = list(target_unix_users.chrome.passwords())

    assert len(records) == 2

    for record in records:
        assert record.browser == "chrome"
        assert record.decrypted_username == "username"
        assert record.decrypted_password == "password"

    assert records[0].url == "https://example.com/"
    assert records[1].url == "https://example.org/"


def test_unix_chrome_passwords_gnome_plugin(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_dir(
        "/root/.config/google-chrome/Default/", absolute_path("_data/plugins/apps/browser/chromium/unix/gnome/")
    )
    target_unix_users.add_plugin(ChromePlugin)

    records = list(target_unix_users.chrome.passwords())

    assert len(records) == 1

    assert records[0].decrypted_username == "username"
    assert records[0].decrypted_password == ""
    assert records[0].url == "https://test.com/"
