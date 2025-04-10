from typing import Iterator, Optional

import pytest
from dissect.util.ts import webkittimestamp
from flow.record.fieldtypes import datetime as dt

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import keychain
from dissect.target.helpers.regutil import VirtualHive
from dissect.target.plugins.apps.browser.chrome import ChromePlugin
from dissect.target.plugins.os.windows.dpapi.dpapi import DPAPIPlugin
from tests._utils import absolute_path
from tests.conftest import add_win_user
from tests.plugins.os.windows.credential.test_lsa import (
    POLICY_KEY_PATH_NT6,
    map_lsa_polkey,
    map_lsa_secrets,
    map_lsa_system_keys,
)
from tests.plugins.os.windows.test__os import map_version_value


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


@pytest.fixture
def target_win_users_dpapi(
    hive_hklm: VirtualHive, hive_hku: VirtualHive, fs_win: VirtualFilesystem, target_win: Target
) -> Iterator[Target]:
    # Add users
    add_win_user(hive_hklm, hive_hku, target_win, sid="S-1-5-18", home="%systemroot%\\system32\\config\\systemprofile")
    add_win_user(
        hive_hklm,
        hive_hku,
        target_win,
        sid="S-1-5-21-1342509979-482553916-3960431919-1000",
        home="C:\\Users\\user",
    )

    # Add system dpapi files
    fs_win.map_dir(
        "Windows/System32/Microsoft/Protect",
        absolute_path("_data/plugins/os/windows/dpapi/fixture/Protect_System32"),
    )

    # Add user dpapi files
    fs_win.map_dir(
        "Users/User/AppData/Roaming/Microsoft/Protect",
        absolute_path("_data/plugins/os/windows/dpapi/fixture/Protect_User"),
    )

    # Add registry dpapi keys
    map_lsa_system_keys(hive_hklm, {"Data": "8fa8e1fb", "GBG": "a6e23eb8", "JD": "fe5ffdaf", "Skew1": "6e289261"})
    map_lsa_polkey(
        hive_hklm,
        POLICY_KEY_PATH_NT6,
        bytes.fromhex(
            "00000001ecffe17b2a997440aa939adbff26f1fc0300000000000000676f5836"
            "37c3e0e7b9edf43b3b29b1d0d24cb6bfc60e0fc4dc446e7d244d303533b90a2b"
            "d732fcf985748a8917aea73e9d0b290ee4ba2f53e6a9a0ac9b3c9b26e721b01b"
            "7a6c1f92b517e2a33f5f6de7f736716793b19872059595e6b4dc888d19d1d615"
            "d602bed553478c411d2fed045602ddbb5adc31c9901021ad339bca368bdb554f"
            "fe074a7074528d5e9dcbb467"
        ),
    )
    map_lsa_secrets(
        hive_hklm,
        {
            "DPAPI_SYSTEM": bytes.fromhex(
                "000000017c3e71eca8fb4eed03ea4361fbc783870300000000000000af64ca32"
                "a15059f8e38f328a5f16d063939bdbb9321ba159dcafd9cdf316d82f89a829d7"
                "58024b276d099ef2290ca46fc7b2635568500bf2d31ed8ce1e0330345cca5ef3"
                "e8d18399a22ae88db12872ee5bb0c1f0dd3b83066269d0d9618b19bb"
            )
        },
    )

    target_win.add_plugin(DPAPIPlugin)
    yield target_win


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

    map_version_value(target_win_users_dpapi, "CurrentVersion", 10.0)

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

    map_version_value(target_win_users_dpapi, "CurrentVersion", 10.0)

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
