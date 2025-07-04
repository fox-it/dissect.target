from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from asn1crypto.algos import EncryptionAlgorithmId
from flow.record.fieldtypes import datetime as dt

from dissect.target.helpers import keychain
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.plugins.apps.browser.firefox import (
    CKA_ID,
    FirefoxPlugin,
    decrypt,
    query_master_key,
    retrieve_master_key,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_firefox_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Target:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\g1rbw8y7.default-release\\",
        absolute_path("_data/plugins/apps/browser/firefox/"),
    )

    target_win_users.add_plugin(FirefoxPlugin)

    return target_win_users


@pytest.fixture
def target_firefox_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Target:
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/", absolute_path("_data/plugins/apps/browser/firefox/")
    )
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/default/"),
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
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_history(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.firefox.history())

    assert len(records) == 24
    assert {"firefox"} == {record.browser for record in records}

    assert records[0].url == "https://www.mozilla.org/privacy/firefox/"
    assert records[0].id == "1"
    assert records[0].description == "47356411089529"
    assert records[0].visit_count == 1
    assert records[0].ts == dt("2021-12-01T10:42:05.742000+00:00")


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_downloads(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.firefox.downloads())

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
def test_firefox_cookies(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)

    records = list(target_platform.firefox.cookies())

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
def test_firefox_extensions(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)

    records = list(target_platform.firefox.extensions())

    assert {"firefox"} == {record.browser for record in records}
    assert len(records) == 2
    assert records[0].id == "uBlock0@raymondhill.net"
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
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_passwords(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)

    records = list(target_platform.firefox.passwords())
    assert len(records) == 2

    assert records[0].browser == "firefox"
    assert records[0].decrypted_username == "username"
    assert records[0].encrypted_password == bytes.fromhex(
        "303a0410f8000000000000000000000000000001301406082a864886f70d030704081d993c26413915090410d9f1d0595158040a88850f9bcfbd36cf"
    )
    assert records[0].decrypted_password == "password"

    assert records[1].browser == "firefox"
    assert records[1].decrypted_username == "username"
    assert records[1].encrypted_password == bytes.fromhex(
        "303a0410f8000000000000000000000000000001301406082a864886f70d030704086fc7f57e0d7c456d04109b40eb0ebf5275d3a3a26f46a910b975"
    )
    assert records[1].decrypted_password == "password"


def test_unix_firefox_passwords_with_primary_password(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
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
    assert records[0].encrypted_password == bytes.fromhex(
        "303a0410f8000000000000000000000000000001301406082a864886f70d03070408cd349ac9ccc45c950410724daaeb9d2f85491e4e1d08597ecf2d"
    )
    assert records[0].decrypted_password == "password"


def test_firefox_oculus_history(target_firefox_oculus: Target) -> None:
    records = list(target_firefox_oculus.firefox.history())

    assert len(records) == 191
    assert {"firefox"} == {record.browser for record in records}

    assert records[0].url == "https://webxr.today/"
    assert records[0].id == "1"
    assert records[0].description == "47356570952011"
    assert records[0].ts == dt("2021-11-04 13:29:30.780000+00:00")


def test_firefox_oculus_cookies(target_firefox_oculus: Target) -> None:
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


def test_firefox_oculus_extensions(target_firefox_oculus: Target) -> None:
    records = list(target_firefox_oculus.firefox.extensions())

    assert {"firefox"} == {record.browser for record in records}
    assert len(records) == 5
    assert records[0].id == "default-theme@mozilla.org"
    assert records[0].ts_install == dt("2021-11-04 13:29:29.988000+00:00")
    assert records[0].ts_update == dt("1970-01-01 00:00:00+00:00")
    assert records[0].ext_path is None
    assert records[0].permissions == []


@pytest.fixture
def path_key4(fs_unix: VirtualFilesystem) -> TargetPath:
    fs_unix.map_file(
        "/key4.db",
        absolute_path("_data/plugins/apps/browser/firefox/key4.db"),
    )
    return TargetPath(fs_unix, "/key4.db")


PRIMARY_PASSWORD = "PrimaryPassword"


@pytest.fixture
def path_key4_primary_password(fs_unix: VirtualFilesystem) -> TargetPath:
    fs_unix.map_file(
        "/key4.db",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/primary/key4.db"),
    )
    return TargetPath(fs_unix, "/key4.db")


@pytest.fixture
def logins() -> dict[str, str]:
    return {
        "username": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIFVMX6MyYxpBBC2j8K+bCEaE9/FmqE1wo2A",
        "password": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECB2ZPCZBORUJBBDZ8dBZUVgECoiFD5vPvTbP",
    }


@pytest.fixture
def logins_with_primary_password() -> dict[str, str]:
    return {
        "username": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECPEZvPh6dhBkBBB3/O2puJy1NiBUo5gS8hZh",
        "password": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECM00msnMxFyVBBByTarrnS+FSR5OHQhZfs8t",
    }


@pytest.fixture
def decrypted() -> dict[str, str]:
    return {
        "username": "username",
        "password": "password",
    }


def test_decrypt_is_succesful(path_key4: TargetPath, logins: dict[str, str], decrypted: dict[str, str]) -> None:
    dec_username, dec_password = decrypt(logins.get("username"), logins.get("password"), path_key4)
    assert dec_username == decrypted.get("username")
    assert dec_password == decrypted.get("password")


@patch("dissect.target.plugins.apps.browser.firefox.retrieve_master_key", side_effect=ValueError(""))
def test_decrypt_bad_master_key(path_key4: TargetPath, logins: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="Failed to decrypt password using keyfile:"):
        decrypt(logins.get("username"), logins.get("password"), path_key4)


def test_decrypt_with_primary_password_is_succesful(
    path_key4_primary_password: TargetPath, logins_with_primary_password: dict[str, str], decrypted: dict[str, str]
) -> None:
    dec_username, dec_password = decrypt(
        logins_with_primary_password.get("username"),
        logins_with_primary_password.get("password"),
        path_key4_primary_password,
        PRIMARY_PASSWORD,
    )
    assert dec_username == decrypted.get("username")
    assert dec_password == decrypted.get("password")


def test_decrypt_with_bad_primary_password_is_unsuccesful(
    path_key4_primary_password: TargetPath,
    logins_with_primary_password: dict[str, str],
) -> None:
    with pytest.raises(
        ValueError, match="Failed to decrypt password using keyfile: /key4.db, password: BAD_PRIMARY_PASSWORD"
    ):
        decrypt(
            logins_with_primary_password.get("username"),
            logins_with_primary_password.get("password"),
            path_key4_primary_password,
            "BAD_PRIMARY_PASSWORD",
        )


def test_retrieve_master_key_is_succesful(path_key4: TargetPath) -> None:
    key, algorithm = retrieve_master_key(b"", path_key4)

    assert EncryptionAlgorithmId.map(algorithm) == "pbes2"
    assert key.hex() == "452c2f920285f794614af1c2d99ed331940d73298a526140"


@patch("dissect.target.plugins.apps.browser.firefox.query_master_key", return_value=(b"aaaa", "BAD_CKA_VALUE"))
def test_retrieve_master_key_bad_cka_value(mock_target: Target, path_key4: TargetPath) -> None:
    with pytest.raises(ValueError, match="Password master key CKA_ID 'BAD_CKA_VALUE' is not equal to expected value"):
        retrieve_master_key(b"", path_key4)


def test_query_master_key(path_key4: TargetPath) -> None:
    master_key, master_key_cka = query_master_key(path_key4)

    assert isinstance(master_key, bytes)
    assert len(master_key) == 148

    assert isinstance(master_key_cka, bytes)
    assert len(master_key_cka) == 16
    assert master_key_cka == CKA_ID
