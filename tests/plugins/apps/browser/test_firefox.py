from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target.helpers import keychain
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.plugins.apps.browser.firefox import (
    FirefoxPlugin,
    decrypt_master_key,
    decrypt_value,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_firefox_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\g1rbw8y7.default-release\\",
        absolute_path("_data/plugins/apps/browser/firefox/generic/"),
    )

    target_win_users.add_plugin(FirefoxPlugin)

    return target_win_users


@pytest.fixture
def target_firefox_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Target:
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/", absolute_path("_data/plugins/apps/browser/firefox/generic/")
    )

    target_unix_users.add_plugin(FirefoxPlugin)

    return target_unix_users


@pytest.fixture
def target_firefox_oculus(target_android: Target, fs_android: VirtualFilesystem) -> Target:
    fs_android.map_dir(
        "/data/data/org.mozilla.vrbrowser",
        absolute_path("_data/plugins/apps/browser/firefox/android/org.mozilla.vrbrowser"),
    )

    target_android.add_plugin(FirefoxPlugin)

    return target_android


@pytest.mark.parametrize(
    ("target_platform", "expected_source"),
    [
        (
            "target_firefox_win",
            "C:\\Users\\John\\AppData\\local\\Mozilla\\Firefox\\Profiles\\g1rbw8y7.default-release\\places.sqlite",
        ),
        (
            "target_firefox_unix",
            "/root/.mozilla/firefox/g1rbw8y7.default-release/places.sqlite",
        ),
    ],
)
def test_firefox_history(target_platform: str, expected_source: str, request: pytest.FixtureRequest) -> None:
    target: Target = request.getfixturevalue(target_platform)
    records = list(target.firefox.history())

    assert len(records) == 24
    assert {"firefox"} == {record.browser for record in records}

    assert records[0].ts == dt("2021-12-01T10:42:05.742000+00:00")
    assert records[0].browser == "firefox"
    assert records[0].id == 1
    assert records[0].url == "https://www.mozilla.org/privacy/firefox/"
    assert not records[0].title
    assert not records[0].description
    assert records[0].host == "www.mozilla.org"
    assert records[0].visit_type == 1
    assert records[0].visit_count == 1
    assert records[0].hidden
    assert not records[0].typed
    assert records[0].session == 0
    assert not records[0].from_visit
    assert not records[0].from_url
    assert records[0].source == expected_source


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_downloads(target_platform: str, request: pytest.FixtureRequest) -> None:
    target: Target = request.getfixturevalue(target_platform)
    records = list(target.firefox.downloads())

    assert len(records) == 3
    assert {"firefox"} == {record.browser for record in records}

    assert records[0].id == 1
    assert records[0].ts_start == dt("2021-12-01T10:57:01.175000+00:00")
    assert records[0].ts_end == dt("2021-12-01T10:57:01.321000+00:00")
    assert (
        records[0].url
        == "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B2098EF96-29DB"
        "-B268-0B90-01AD59CD5C17%7D%26lang%3Dnl%26browser%3D3%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needs"
        "admin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/update2/installers/ChromeSetup.exe"
    )


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_cookies(target_platform: str, request: pytest.FixtureRequest) -> None:
    target: Target = request.getfixturevalue(target_platform)

    records = list(target.firefox.cookies())

    assert len(records) == 4
    assert {"firefox"} == {record.browser for record in records}

    assert records[0].ts_created == dt("2023-07-13 09:53:47.460676+00:00")
    assert sorted(c.name for c in records) == [
        "_lr_env_src_ats",
        "_lr_retry_request",
        "_uc_referrer",
        "_uc_referrer",
    ]


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_extensions(target_platform: str, request: pytest.FixtureRequest) -> None:
    target: Target = request.getfixturevalue(target_platform)

    records = list(target.firefox.extensions())

    assert {"firefox"} == {record.browser for record in records}
    assert len(records) == 2
    assert records[0].extension_id == "uBlock0@raymondhill.net"
    assert records[0].ts_install == dt("2024-04-23 07:07:21.516000+00:00")
    assert records[0].ts_update == dt("2024-04-23 07:07:21.516000+00:00")
    assert (
        records[0].ext_path == "C:\\Users\\Win11\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
        "\\9nxit8q0.default-release\\extensions\\uBlock0@raymondhill.net.xpi"
    )
    assert records[0].permissions == [
        "alarms",
        "dns",
        "menus",
        "privacy",
        "storage",
        "tabs",
        "unlimitedStorage",
        "webNavigation",
        "webRequest",
        "webRequestBlocking",
    ]
    assert records[1].permissions == []


@pytest.mark.parametrize(
    "target_platform",
    [
        "target_firefox_win",
        "target_firefox_unix",
    ],
)
def test_firefox_passwords(target_platform: str, request: pytest.FixtureRequest) -> None:
    target: Target = request.getfixturevalue(target_platform)

    records = list(target.firefox.passwords())
    assert len(records) == 2

    assert records[0].browser == "firefox"
    assert records[0].decrypted_username == "username"
    assert records[0].encrypted_password is None
    assert records[0].decrypted_password == "password"

    assert records[1].browser == "firefox"
    assert records[1].decrypted_username == "username"
    assert records[1].encrypted_password is None
    assert records[1].decrypted_password == "password"


def test_firefox_passwords_unix_primary_password(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/primary/"),
    )
    target_unix_users.add_plugin(FirefoxPlugin)

    keychain.register_key(
        keychain.KeyType.PASSPHRASE,
        "PrimaryPassword",
        identifier=None,
        provider="browser",
    )

    records = list(target_unix_users.firefox.passwords())

    assert len(records) == 1

    assert records[0].browser == "firefox"
    assert records[0].username == "root"
    assert records[0].user_home == "/root"
    assert records[0].decrypted_username == "username"
    assert records[0].encrypted_password is None
    assert records[0].decrypted_password == "password"


def test_firefox_history_oculus(target_firefox_oculus: Target) -> None:
    records = list(target_firefox_oculus.firefox.history())

    assert len(records) == 191
    assert {"firefox"} == {record.browser for record in records}

    assert records[0].url == "https://webxr.today/"
    assert records[0].id == 1
    assert not records[0].description
    assert records[0].ts == dt("2021-11-04 13:29:30.780000+00:00")


def test_firefox_cookies_oculus(target_firefox_oculus: Target) -> None:
    records = list(target_firefox_oculus.firefox.cookies())

    assert len(records) == 33
    assert {"firefox"} == {record.browser for record in records}

    assert records[0].ts_created == dt("2023-07-06 07:50:55.352988+00:00")
    assert sorted(c.name for c in records) == [
        "AEC",
        "AWSALBTGCORS",
        "CONSENT",
        "Features",
        "Locale",
        "NID",
        "OptanonConsent",
        "SNID",
        "SOCS",
        "Session-Id",
        "Tag",
        "Tag",
        "Tag",
        "Tag",
        "VISITOR_INFO1_LIVE",
        "_ga",
        "_ga_18EC69JQ0P",
        "_ga_2VC139B3XV",
        "_gat_gtag_UA_36116321_2",
        "_gid",
        "_hjFirstSeen",
        "count",
        "is-proton-user",
        "lst",
        "lst",
        "mp_abe3945ad0ddaadc3d987393d8d7c2ce_mixpanel",
        "session_id",
        "spid.6b32",
        "spses.6b32",
        "visid_incap_1329355",
        "visid_incap_2188750",
        "visid_incap_2295456",
        "visid_incap_2809573",
    ]


def test_firefox_extensions_oculus(target_firefox_oculus: Target) -> None:
    records = list(target_firefox_oculus.firefox.extensions())

    assert {"firefox"} == {record.browser for record in records}
    assert len(records) == 5
    assert records[0].extension_id == "default-theme@mozilla.org"
    assert records[0].ts_install == dt("2021-11-04 13:29:29.988000+00:00")
    assert records[0].ts_update == dt("1970-01-01 00:00:00+00:00")
    assert records[0].ext_path is None
    assert records[0].permissions == []


@pytest.fixture
def path_key4(fs_unix: VirtualFilesystem) -> TargetPath:
    fs_unix.map_file(
        "/key4.db",
        absolute_path("_data/plugins/apps/browser/firefox/generic/key4.db"),
    )
    return TargetPath(fs_unix, "/key4.db")


@pytest.fixture
def path_key4_primary_password(fs_unix: VirtualFilesystem) -> TargetPath:
    fs_unix.map_file(
        "/key4.db",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/primary/key4.db"),
    )
    return TargetPath(fs_unix, "/key4.db")


def test_passwords(path_key4: TargetPath) -> None:
    """Test if we can decrypt a password entry with an empty Firefox primary password."""

    key = decrypt_master_key(path_key4, b"")

    b64_username = "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIFVMX6MyYxpBBC2j8K+bCEaE9/FmqE1wo2A"
    b64_password = "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECB2ZPCZBORUJBBDZ8dBZUVgECoiFD5vPvTbP"

    plaintext_username = decrypt_value(b64_username, key)
    assert plaintext_username == b"username"

    plaintext_password = decrypt_value(b64_password, key)
    assert plaintext_password == b"password"


def test_passwords_primary_password(path_key4_primary_password: TargetPath) -> None:
    """Test if we can decrypt a password entry with a Firefox primary password."""

    key = decrypt_master_key(path_key4_primary_password, b"PrimaryPassword")

    b64_username = "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECPEZvPh6dhBkBBB3/O2puJy1NiBUo5gS8hZh"
    plaintext_username = decrypt_value(b64_username, key)
    assert plaintext_username == b"username"

    b64_password = "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECM00msnMxFyVBBByTarrnS+FSR5OHQhZfs8t"
    plaintext_password = decrypt_value(b64_password, key)
    assert plaintext_password == b"password"


def test_passwords_no_master_key() -> None:
    """Test if a fitting exception is raised when omitting a decryption key."""

    with pytest.raises(ValueError, match="Not a valid TDES key"):
        decrypt_value("MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIFVMX6MyYxpBBC2j8K+bCEaE9/FmqE1wo2A", b"")


def test_passwords_decrypt_master_key_invalid_primary_password(path_key4_primary_password: TargetPath) -> None:
    """Test if a fitting exception is raised when providing an invalid primary password."""

    with pytest.raises(ValueError, match=re.escape("Master key decryption failed.")):
        decrypt_master_key(path_key4_primary_password, b"BAD_PRIMARY_PASSWORD")


def test_passwords_decrypt_master_key(path_key4: TargetPath) -> None:
    """Test if we can decrypt a master key with no primary password."""

    key = decrypt_master_key(path_key4, b"")
    assert key.hex() == "452c2f920285f794614af1c2d99ed331940d73298a526140"


def test_passwords_decrypt_aes() -> None:
    """Test if we correctly decrypt Firefox 144.0 passwords. Data generated on a Windows 11 24H2 VM.

    ``key4.db`` file contains an empty entry in the ``nssPrivate`` table to test if we correctly grab
    the last row of the table when decrypting the master key.
    """

    key4_file = absolute_path("_data/plugins/apps/browser/firefox/passwords/144.0/key4.db")
    key = decrypt_master_key(key4_file, b"")

    b64_username = "MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBC43iUHA33gEegQQOh2RYVABBDpNU6x1Q9IS20qq55IPy8K"
    plaintext_username = decrypt_value(b64_username, key)
    assert plaintext_username == b"username"

    b64_password = "MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBBnaT+EZVKmFCEX256l7Z06BBDuNPzjclPu77lO5m8ZC2HP"
    plaintext_password = decrypt_value(b64_password, key)
    assert plaintext_password == b"password"

    b64_unknown = "MEMEEPgAAAAAAAAAAAAAAAAAAAEwHQYJYIZIAWUDBAEqBBDH5u9D6iZZ7WbagSHJpDGnBBCeA5eSi8teghT3FHogzqOF"
    assert decrypt_value(b64_unknown, key) == b""


def test_passwords_backup(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we find ``logins-backup.json`` files."""

    fs_win.map_dir(
        "Users/John/AppData/Roaming/Mozilla/Firefox/Profiles/8jb1c7qs.default-release",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/144.0/"),
    )
    target_win_users.add_plugin(FirefoxPlugin)

    records = list(target_win_users.firefox.passwords())
    assert len(records) == 3

    assert records[-1].source == "C:\\Users\\John\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\8jb1c7qs.default-release\\logins-backup.json"  # noqa: E501
