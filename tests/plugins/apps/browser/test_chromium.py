from typing import Iterator

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser.chromium import ChromiumPlugin, decrypt_v10
from tests._utils import absolute_path


@pytest.fixture
def target_chromium_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Chromium\\User Data\\Default\\",
        absolute_path("_data/plugins/apps/browser/chromium/"),
    )

    target_win_users.add_plugin(ChromiumPlugin)

    yield target_win_users


@pytest.fixture
def target_chromium_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Iterator[Target]:
    fs_unix.map_dir("/root/.config/chromium/Default/", absolute_path("_data/plugins/apps/browser/chromium/"))
    target_unix_users.add_plugin(ChromiumPlugin)

    yield target_unix_users


@pytest.mark.parametrize(
    "target_platform",
    ["target_chromium_win", "target_chromium_unix"],
)
def test_chromium_history(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.chromium.history())

    assert len(records) == 5
    assert set(["chromium"]) == set(record.browser for record in records)

    assert (
        records[0].url
        == "https://www.google.com/search?q=fox-it+github+dissect&oq=fox-it+github+dissect&gs_lcrp=EgZjaHJvbWUyBggA"
        "EEUYOTIHCAEQIRigAdIBCDU2OTNqMGo3qAIAsAIA&sourceid=chrome&ie=UTF-8"
    )
    assert records[0].id == "1"
    assert records[0].visit_count == 2
    assert records[0].ts == dt("2022-12-22T12:14:26.396332+00:00")


@pytest.mark.parametrize(
    "target_platform",
    ["target_chromium_win", "target_chromium_unix"],
)
def test_chromium_downloads(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.chromium.downloads())

    assert len(records) == 1
    assert set(["chromium"]) == set(record.browser for record in records)

    assert records[0].id == 1
    assert records[0].ts_start == dt("2022-12-22T12:14:38.440832+00:00")
    assert records[0].ts_end == dt("2022-12-22T12:14:38.964170+00:00")
    assert records[0].url == "https://codeload.github.com/fox-it/dissect/zip/refs/heads/main"


@pytest.mark.parametrize(
    "target_platform",
    ["target_chromium_win", "target_chromium_unix"],
)
def test_chromium_cookies(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.chromium.cookies())

    assert len(records) == 5
    assert set(["chromium"]) == set(record.browser for record in records)

    assert sorted([*map(lambda c: c.name, records)]) == [
        "pl",
        "ssa-did",
        "ssa-sid",
        "tbb",
        "twk-theme",
    ]


@pytest.mark.parametrize(
    "target_platform",
    ["target_chromium_win", "target_chromium_unix"],
)
def test_chromium_extensions(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.chromium.extensions())

    assert len(records) == 4
    assert set(["chromium"]) == set(record.browser for record in records)

    assert records[0].ts_install == dt("2023-04-18T08:43:37.773874+00:00")
    assert records[0].ts_update == dt("2023-04-18T08:43:37.773874+00:00")
    assert records[0].name == "Web Store"
    assert records[0].version == "0.2"
    assert records[0].id == "ahfgeienlihckogmohjhadlkjgocpleb"


def test_windows_chromium_passwords(target_chromium_win: Target) -> None:
    records = list(target_chromium_win.chromium.passwords())

    assert len(records) == 2

    for record in records:
        assert record.browser == "chromium"
        assert record.decrypted_username == "username"
        assert record.decrypted_password is None

    assert records[0].url == "https://example.com/"
    assert records[1].url == "https://example.org/"


def test_unix_chromium_passwords_basic(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_dir("/root/.config/chromium/Default/", absolute_path("_data/plugins/apps/browser/chromium/unix/basic/"))
    target_unix_users.add_plugin(ChromiumPlugin)

    records = list(target_unix_users.chromium.passwords())

    assert len(records) == 2

    for record in records:
        assert record.browser == "chromium"
        assert record.decrypted_username == "username"
        assert record.decrypted_password == "password"

    assert records[0].url == "https://example.com/"
    assert records[1].url == "https://example.org/"


def test_unix_chromium_passwords_gnome(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_dir("/root/.config/chromium/Default/", absolute_path("_data/plugins/apps/browser/chromium/unix/gnome/"))
    target_unix_users.add_plugin(ChromiumPlugin)

    records = list(target_unix_users.chromium.passwords())

    assert len(records) == 1

    assert records[0].decrypted_username == "username"
    assert records[0].decrypted_password is None
    assert records[0].url == "https://test.com/"


def test_decrypt_v10():
    encrypted = b"v10\xd0&E\xbb\x85\xe7_\xfd\xf8\x93\x90/\x08{'\xa9"
    decrypted = decrypt_v10(encrypted)
    assert decrypted == "password"
