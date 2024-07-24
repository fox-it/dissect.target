from typing import Iterator
from unittest.mock import patch

import pytest
from _pytest.fixtures import fixture
from asn1crypto.algos import EncryptionAlgorithmId
from flow.record.fieldtypes import datetime as dt

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
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


@pytest.fixture
def target_firefox_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\g1rbw8y7.default-release\\",
        absolute_path("_data/plugins/apps/browser/firefox/"),
    )

    target_win_users.add_plugin(FirefoxPlugin)

    yield target_win_users


@pytest.fixture
def target_firefox_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Iterator[Target]:
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/", absolute_path("_data/plugins/apps/browser/firefox/")
    )
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/default/"),
    )

    target_unix_users.add_plugin(FirefoxPlugin)

    yield target_unix_users


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_history(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.firefox.history())

    assert len(records) == 24
    assert set(["firefox"]) == set(record.browser for record in records)

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
    assert set(["firefox"]) == set(record.browser for record in records)

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
    assert set(["firefox"]) == set(record.browser for record in records)

    assert sorted([*map(lambda c: c.name, records)]) == [
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

    assert set(["firefox"]) == set(record.browser for record in records)
    assert len(records) == 2
    assert records[0].id == "uBlock0@raymondhill.net"
    assert records[0].ts_install == dt("2024-04-23 07:07:21+00:00")
    assert records[0].ts_update == dt("2024-04-23 07:07:21+00:00")
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
def test_firefox_password_plugin(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)

    records = list(target_platform.firefox.passwords())
    assert len(records) == 2

    for record in records:
        assert record.browser == "firefox"
        assert record.decrypted_username == "username"
        assert record.decrypted_password == "password"


def test_unix_firefox_password_plugin_with_primary_password(
    target_unix_users: Target, fs_unix: VirtualFilesystem
) -> None:
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

    for record in records:
        assert record.browser == "firefox"
        assert record.username == "root"
        assert record.user_home == "/root"

        assert record.decrypted_username == "username"
        assert record.decrypted_password == "password"


@fixture
def path_key4(fs_unix):
    fs_unix.map_file(
        "/key4.db",
        absolute_path("_data/plugins/apps/browser/firefox/key4.db"),
    )
    return TargetPath(fs_unix, "/key4.db")


PRIMARY_PASSWORD = "PrimaryPassword"


@fixture
def path_key4_primary_password(fs_unix):
    fs_unix.map_file(
        "/key4.db",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/primary/key4.db"),
    )
    return TargetPath(fs_unix, "/key4.db")


@fixture
def logins():
    return {
        "username": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIFVMX6MyYxpBBC2j8K+bCEaE9/FmqE1wo2A",
        "password": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECB2ZPCZBORUJBBDZ8dBZUVgECoiFD5vPvTbP",
    }


@fixture
def logins_with_primary_password():
    return {
        "username": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECPEZvPh6dhBkBBB3/O2puJy1NiBUo5gS8hZh",
        "password": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECM00msnMxFyVBBByTarrnS+FSR5OHQhZfs8t",
    }


@fixture
def decrypted():
    return {
        "username": "username",
        "password": "password",
    }


def test_decrypt_is_succesful(path_key4, logins, decrypted):
    dec_username, dec_password = decrypt(logins.get("username"), logins.get("password"), path_key4)
    assert dec_username == decrypted.get("username")
    assert dec_password == decrypted.get("password")


@patch("dissect.target.plugins.apps.browser.firefox.retrieve_master_key", side_effect=ValueError(""))
def test_decrypt_bad_master_key(mock_target, path_key4, logins):
    with pytest.raises(ValueError):
        decrypt(logins.get("username"), logins.get("password"), path_key4)


def test_decrypt_with_primary_password_is_succesful(
    path_key4_primary_password, logins_with_primary_password, decrypted
):
    dec_username, dec_password = decrypt(
        logins_with_primary_password.get("username"),
        logins_with_primary_password.get("password"),
        path_key4_primary_password,
        PRIMARY_PASSWORD,
    )
    assert dec_username == decrypted.get("username")
    assert dec_password == decrypted.get("password")


def test_decrypt_with_bad_primary_password_is_unsuccesful(
    path_key4_primary_password,
    logins_with_primary_password,
):
    with pytest.raises(ValueError) as e:
        decrypt(
            logins_with_primary_password.get("username"),
            logins_with_primary_password.get("password"),
            path_key4_primary_password,
            "BAD_PRIMARY_PASSWORD",
        )
        assert e.msg == "Failed to decrypt password using keyfile /key4.db and password 'BAD_PRIMARY_PASSWORD'"


def test_retrieve_master_key_is_succesful(path_key4):
    key, algorithm = retrieve_master_key(b"", path_key4)

    assert EncryptionAlgorithmId.map(algorithm) == "pbes2"
    assert key.hex() == "452c2f920285f794614af1c2d99ed331940d73298a526140"


@patch("dissect.target.plugins.apps.browser.firefox.query_master_key", return_value=(b"aaaa", "BAD_CKA_VALUE"))
def test_retrieve_master_key_bad_cka_value(mock_target, path_key4):
    with pytest.raises(ValueError) as e:
        retrieve_master_key(b"", path_key4)
        assert "Password master key CKA_ID 'BAD_CKA_VALUE' is not equal to expected value" in e.msg


def test_query_master_key(path_key4):
    master_key, master_key_cka = query_master_key(path_key4)

    assert isinstance(master_key, bytes)
    assert len(master_key) == 148

    assert isinstance(master_key_cka, bytes)
    assert len(master_key_cka) == 16
    assert master_key_cka == CKA_ID
