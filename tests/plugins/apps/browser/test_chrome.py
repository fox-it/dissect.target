from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from dissect.util.ts import webkittimestamp
from flow.record.fieldtypes import datetime as dt

from dissect.target.helpers import keychain
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

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.helpers.regutil import VirtualHive
    from dissect.target.target import Target


@pytest.fixture
def target_chrome_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\",
        absolute_path("_data/plugins/apps/browser/chrome/generic"),
    )
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\",
        absolute_path("_data/plugins/apps/browser/chrome/generic"),
    )

    target_win_users.add_plugin(ChromePlugin)

    return target_win_users


@pytest.fixture
def target_chrome_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Target:
    fs_unix.map_dir("/root/.config/google-chrome/Default/", absolute_path("_data/plugins/apps/browser/chrome/generic"))
    fs_unix.map_dir(
        "/root/.config/google-chrome/Profile 1/", absolute_path("_data/plugins/apps/browser/chrome/generic")
    )

    target_unix_users.add_plugin(ChromePlugin)

    return target_unix_users


@pytest.fixture
def target_chrome_win_snapshot(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\116.0.5038.150\\Default",
        absolute_path("_data/plugins/apps/browser/chrome/generic"),
    )

    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\116.0.5038.150\\Profile 1",
        absolute_path("_data/plugins/apps/browser/chrome/generic"),
    )

    target_win_users.add_plugin(ChromePlugin)

    return target_win_users


@pytest.mark.parametrize(
    "target_platform",
    ["target_chrome_win", "target_chrome_unix", "target_chrome_win_snapshot"],
)
def test_chrome_history(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.chrome.history())

    assert len(records) == 10
    assert {"chrome"} == {record.browser for record in records}

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

    assert len(records) == 2
    assert {"chrome"} == {record.browser for record in records}

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

    assert len(records) == 16
    assert {"chrome"} == {record.browser for record in records}

    assert records[0].ts_install == dt("2022-11-24T15:20:43.682152+00:00")
    assert records[0].ts_update == dt("2022-11-24T15:20:43.682152+00:00")
    assert records[0].name == "Web Store"
    assert records[0].version == "0.2"
    assert records[0].id == "ahfgeienlihckogmohjhadlkjgocpleb"


def test_windows_chrome_passwords_plugin(target_chrome_win: Target) -> None:
    records = list(target_chrome_win.chrome.passwords())

    assert len(records) == 4

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
    fs_unix.map_dir(
        "/root/.config/google-chrome/Profile 1/", absolute_path("_data/plugins/apps/browser/chromium/unix/basic/")
    )
    target_unix_users.add_plugin(ChromePlugin)

    records = list(target_unix_users.chrome.passwords())

    assert len(records) == 4

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
    fs_unix.map_dir(
        "/root/.config/google-chrome/Profile 1/", absolute_path("_data/plugins/apps/browser/chromium/unix/gnome/")
    )
    target_unix_users.add_plugin(ChromePlugin)

    records = list(target_unix_users.chrome.passwords())

    assert len(records) == 2

    assert records[0].decrypted_username == "username"
    assert records[0].decrypted_password is None
    assert records[0].url == "https://test.com/"


@pytest.fixture
def target_win_users_dpapi(
    hive_hklm: VirtualHive, hive_hku: VirtualHive, fs_win: VirtualFilesystem, target_win: Target
) -> Target:
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
        absolute_path("_data/plugins/os/windows/dpapi/fixture/windows_10/Protect_System32"),
    )

    # Add user dpapi files
    fs_win.map_dir(
        "Users/User/AppData/Roaming/Microsoft/Protect",
        absolute_path("_data/plugins/os/windows/dpapi/fixture/windows_10/Protect_User"),
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
    return target_win


@pytest.fixture
def target_win_11_users_dpapi(
    hive_hklm: VirtualHive, hive_hku: VirtualHive, fs_win: VirtualFilesystem, target_win: Target
) -> Target:
    # Add users
    add_win_user(hive_hklm, hive_hku, target_win, sid="S-1-5-18", home="C:\\WINDOWS\\system32\\config\\systemprofile")
    add_win_user(
        hive_hklm,
        hive_hku,
        target_win,
        sid="S-1-5-21-3656658933-2463154391-3030686545-1001",
        home="C:\\Users\\User",
    )

    # Add system dpapi files
    fs_win.map_dir(
        "Windows/System32/Microsoft/Protect",
        absolute_path("_data/plugins/os/windows/dpapi/fixture/windows_11/Protect_System32"),
    )

    # Add user dpapi files
    fs_win.map_dir(
        "Users/User/AppData/Roaming/Microsoft/Protect",
        absolute_path("_data/plugins/os/windows/dpapi/fixture/windows_11/Protect_User"),
    )

    # Add registry dpapi keys
    map_lsa_system_keys(hive_hklm, {"Data": "5ef65665", "GBG": "df865f5a", "JD": "bdee0692", "Skew1": "73bc8e8c"})
    map_lsa_polkey(
        hive_hklm,
        POLICY_KEY_PATH_NT6,
        bytes.fromhex(
            "00000001ecffe17b2a997440aa939adbff26f1fc0300000000000000da616d31"
            "4c9d457773de28cbf0ba721b98904cd68f7d0442ca7ad8e5409fe4d8bf7da10c"
            "8612389537bd7789d6bba9a4632c3ff90a91455dcea3869b87c04c3970b2f6f4"
            "8071b486b84c00d4fa3fab4f2f67578676fc4ef3072d9801b2ab062a758b4173"
            "8eee755b57dee2f59d42166c0827d7ecb33903b6a52eb6f5f96b6b9fba9a7ed0"
            "edf84a2be6b732cff0727e9a"
        ),
    )
    map_lsa_secrets(
        hive_hklm,
        {
            "DPAPI_SYSTEM": bytes.fromhex(
                "0000000195325072efa465ba92ec5edd44c4fefc030000000000000031291c7b"
                "4acb32b7c319c6fd70073435b0f4aa9f6e48451cd225382a0703b6505d75201d"
                "c5c10350492071c92bbc10bebbac687a6caed2d6f2f30d13ff5b744ad56727a8"
                "5bfb8ee9badcf2f784ca65228591356a7cff0aa5ecac645336d55389"
            )
        },
    )

    map_version_value(target_win, "ProductName", "Windows 10 Pro")
    map_version_value(target_win, "CurrentVersion", "10.0")
    map_version_value(target_win, "CurrentBuildNumber", "26100")

    target_win.add_plugin(DPAPIPlugin)
    return target_win


@pytest.mark.parametrize(
    ("keychain_value", "expected_password", "expected_notes"),
    [
        ("user", "StrongPassword", "Example note."),
        ("invalid", None, None),
    ],
)
def test_windows_chrome_passwords_dpapi(
    target_win_users_dpapi: Target,
    fs_win: VirtualFilesystem,
    guarded_keychain: None,
    keychain_value: str,
    expected_password: str | None,
    expected_notes: str | None,
) -> None:
    fs_win.map_dir(
        "Users/user/AppData/Local/Google/Chrome/User Data",
        absolute_path("_data/plugins/apps/browser/chrome/dpapi/windows_10/User_Data"),
    )

    map_version_value(target_win_users_dpapi, "CurrentVersion", 10.0)

    target_win_users_dpapi.add_plugin(ChromePlugin)

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
    assert records[0].encrypted_password == bytes.fromhex(
        "7631304fc7d5702f638993eb325f1075c1464a57cd02b4cf246ed0fd6cf8b2f1e9f5c4551b536a0b5fc973c411"
    )
    assert records[0].decrypted_password == expected_password
    assert records[0].encrypted_notes == bytes.fromhex(
        "76313052fa24300b1592880a5c3bdfbbcfab1fb10450a3bf385f7547cd76ec900a2ca37c5a6104dff0cbe404"
    )
    assert records[0].decrypted_notes == expected_notes


def test_windows_chrome_cookies_dpapi(
    target_win_users_dpapi: Target, fs_win: VirtualFilesystem, guarded_keychain: None
) -> None:
    fs_win.map_dir(
        "Users/user/AppData/Local/Google/Chrome/User Data",
        absolute_path("_data/plugins/apps/browser/chrome/dpapi/windows_10/User_Data"),
    )

    map_version_value(target_win_users_dpapi, "CurrentVersion", 10.0)

    target_win_users_dpapi.add_plugin(ChromePlugin)

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
    base_dirs = [
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Default",
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1",
    ]
    snapshot_dirs = [
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\116.0.5038.150\\Default",
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\119.0.7845.119\\Default",
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\116.0.5038.150\\Profile 1",
        "Users\\John\\AppData\\Local\\Google\\Chrome\\User Data\\Snapshots\\119.0.7845.119\\Profile 1",
    ]
    profile_dirs = base_dirs + snapshot_dirs

    for dir in profile_dirs:
        fs_win.map_dir(
            dir,
            absolute_path("_data/plugins/apps/browser/chrome/generic"),
        )

    target_win_users.add_plugin(ChromePlugin)

    records_list = [
        list(target_win_users.chrome.history()),
        list(target_win_users.chrome.extensions()),
        list(target_win_users.chrome.downloads()),
    ]

    # Loop over the different types of records and verify we have the same amount of records in each profile directory.
    for records in records_list:
        assert {"chrome"} == {record.browser for record in records}

        for base_dir in base_dirs:
            base_path_records = [r for r in records if str(r.source.parent).endswith(base_dir)]

        for snapshot_dir in snapshot_dirs:
            # Retrieve records that are in the snapshot's directory.
            snapshot_records = [r for r in records if str(r.source.parent).endswith(snapshot_dir)]

        # We map the same files in each of the snapshot directories.
        assert len(base_path_records) == len(snapshot_records)


def test_chrome_windows_11_decryption(
    target_win_11_users_dpapi: Target, fs_win: VirtualFilesystem, guarded_keychain: None
) -> None:
    """Test if we can decrypt Windows 11 Google Chrome version 127/130 and newer passwords and cookies.

    Elevation Service usage by Chromium-based browsers (Google Chrome, Microsoft Edge) depend on several environment
    based circumstances (e.g. Windows version, feature flags, account log-in state). To force usage of the Elevation
    Service, run the command(s) below.

    .. code-block::

        (chrome.exe|msedge.exe) --enable-features=UseElevator

    """

    keychain.register_key(
        key_type=keychain.KeyType.PASSPHRASE,
        value="password",
        identifier=None,
        provider="user",
    )

    fs_win.map_dir(
        "Users/user/AppData/Local/Google/Chrome/User Data",
        absolute_path("_data/plugins/apps/browser/chrome/dpapi/windows_11/User_Data"),
    )

    target_win_11_users_dpapi.add_plugin(ChromePlugin)

    passwords = list(target_win_11_users_dpapi.chrome.passwords())
    assert len(passwords) == 2

    assert passwords[0].id == 1
    assert passwords[0].url == "https://elevated-example.com/"
    assert passwords[0].decrypted_username == "username@example.com"
    assert passwords[0].encrypted_password == bytes.fromhex(
        "763230b6ed2338175e5baa4daccc34697aa08809a69ead978a869cf11fabe0cafff7edf2340412"
    )
    assert passwords[0].decrypted_password == "password"
    assert passwords[0].encrypted_notes == bytes.fromhex(
        "763230892774a36593aefaa21416d3268235e98dd5cd7bc15cca023f669cd5df821066eba9de7bf0fe63f690cd"
    )
    assert passwords[0].decrypted_notes == "some note here"
    assert passwords[0].username == "User"

    assert passwords[1].id == 2
    assert passwords[1].url == "https://another-example.com/"
    assert passwords[1].decrypted_username == "username@domain.com"
    assert passwords[1].encrypted_password == bytes.fromhex(
        "763230e470c68414223312778d6345a548616a03be50106d6be9b0bd19b1a3186eecf7a41426a4eca7ed4eeaa0adf400e3c5"
    )
    assert passwords[1].decrypted_password == "MyPasswordIsSecret!"
    assert passwords[1].username == "User"

    cookies = list(target_win_11_users_dpapi.chrome.cookies())
    assert len(cookies) == 2

    assert cookies[0].host == "werkenvoornederland.nl"
    assert cookies[0].name == "ExampleCookieName"
    assert cookies[0].value == "1"

    assert cookies[1].host == "rijksoverheid.nl"
    assert cookies[1].name == "AnotherExampleCookieName"
    assert cookies[1].value == "420"
