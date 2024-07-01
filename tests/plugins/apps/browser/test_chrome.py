from typing import Iterator, Optional

import pytest
from dissect.util.ts import webkittimestamp
from flow.record.fieldtypes import datetime as dt

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import keychain
from dissect.target.plugins.apps.browser.chrome import ChromePlugin
from tests._utils import absolute_path


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


@pytest.fixture
def target_chrome_win_snapshot(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\116.0.5038.150\\Default",
        absolute_path("_data/plugins/apps/browser/chrome/"),
    )

    target_win_users.add_plugin(ChromePlugin)

    yield target_win_users


@pytest.mark.parametrize(
    "target_platform",
    ["target_chrome_win", "target_chrome_unix", "target_chrome_win_snapshot"],
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
    ["target_chrome_win", "target_chrome_unix", "target_chrome_win_snapshot"],
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
    ["target_chrome_win", "target_chrome_unix", "target_chrome_win_snapshot"],
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
        assert record.decrypted_password is None

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
    assert records[0].decrypted_password is None
    assert records[0].url == "https://test.com/"


@pytest.mark.parametrize(
    "keychain_value, expected_password",
    [
        ("user", "StrongPassword"),
        ("invalid", None),
    ],
)
def test_windows_chrome_passwords_dpapi(
    target_win_users_dpapi: Target, fs_win: VirtualFilesystem, keychain_value: str, expected_password: Optional[str]
) -> None:
    fs_win.map_dir(
        "Users/user/AppData/Local/Google/Chrome/User Data",
        absolute_path("_data/plugins/apps/browser/chrome/dpapi/User_Data"),
    )

    target_win_users_dpapi.add_plugin(ChromePlugin)

    keychain.KEYCHAIN.clear()
    keychain.register_key(
        key_type=keychain.KeyType.PASSPHRASE,
        value=keychain_value,
        identifier=None,
        provider="user",
    )

    records = list(target_win_users_dpapi.chrome.passwords())

    assert len(keychain.get_all_keys()) == 1
    assert len(records) == 2

    assert records[0].url == "https://example.com/"
    assert records[0].encrypted_password == "djEwT8fVcC9jiZPrMl8QdcFGSlfNArTPJG7Q/Wz4svHp9cRVG1NqC1/Jc8QR"
    assert records[0].decrypted_password == expected_password


def test_windows_chrome_cookies_dpapi(target_win_users_dpapi: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_dir(
        "Users/user/AppData/Local/Google/Chrome/User Data",
        absolute_path("_data/plugins/apps/browser/chrome/dpapi/User_Data"),
    )

    target_win_users_dpapi.add_plugin(ChromePlugin)

    keychain.KEYCHAIN.clear()
    keychain.register_key(
        key_type=keychain.KeyType.PASSPHRASE,
        value="user",
        identifier=None,
        provider="user",
    )

    records = list(target_win_users_dpapi.chrome.cookies())

    assert len(records) == 4

    assert records[0].ts_created == webkittimestamp(13370000000000000)
    assert records[0].ts_last_accessed == webkittimestamp(13370000000000000)
    assert records[0].browser == "chrome"
    assert records[0].name == "tbb"
    assert records[0].value == "false"
    assert records[0].host == ".tweakers.net"
    assert records[0].is_secure

    assert {c.name: c.value for c in records} == {
        "tbb": "false",
        "twk-theme": "twk-light",
        "GPS": "1",
        "PREF": "tz=Europe.Berlin",
    }


def test_chrome_windows_snapshots(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    base_dir = "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
    snapshot_dirs = [
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\116.0.5038.150\\Default",
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\119.0.7845.119\\Default",
    ]
    profile_dirs = [base_dir] + snapshot_dirs

    for dir in profile_dirs:
        fs_win.map_dir(
            dir,
            absolute_path("_data/plugins/apps/browser/chrome/"),
        )

    target_win_users.add_plugin(ChromePlugin)

    records_list = [
        list(target_win_users.chrome.history()),
        list(target_win_users.chrome.extensions()),
        list(target_win_users.chrome.downloads()),
    ]

    # Loop over the different types of records and verify we have the same amount of records in each profile directory.
    for records in records_list:
        assert set(["chrome"]) == set(record.browser for record in records)

        base_path_records = [r for r in records if str(r.source.parent).endswith(base_dir)]

        for snapshot_dir in snapshot_dirs:
            # Retrieve records that are in the snapshot's directory.
            snapshot_records = [r for r in records if str(r.source.parent).endswith(snapshot_dir)]

            # We map the same files in each of the snapshot directories.
            assert len(base_path_records) == len(snapshot_records)
