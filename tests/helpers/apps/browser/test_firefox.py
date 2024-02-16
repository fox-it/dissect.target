from unittest.mock import patch

from _pytest.fixtures import fixture
from asn1crypto.algos import EncryptionAlgorithmId

from dissect.target.helpers.apps.browser import firefox
from dissect.target.helpers.fsutil import TargetPath
from tests._utils import absolute_path


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
    dec_username, dec_password = firefox.decrypt(logins.get("username"), logins.get("password"), path_key4)
    assert dec_username == decrypted.get("username")
    assert dec_password == decrypted.get("password")


@patch("dissect.target.helpers.apps.browser.firefox.retrieve_master_key", return_value=(b"", ""))
def test_decrypt_bad_master_key(mock_target, path_key4, logins):
    dec_username, dec_password = firefox.decrypt(logins.get("username"), logins.get("password"), path_key4)
    assert dec_username == ""
    assert dec_password == ""


@patch("dissect.target.helpers.apps.browser.firefox.retrieve_master_key", return_value=(b"", "not.existing.algorithm"))
def test_decrypt_unsupported_algoritm(mock_target, path_key4, logins):
    dec_username, dec_password = firefox.decrypt(logins.get("username"), logins.get("password"), path_key4)
    assert dec_username == ""
    assert dec_password == ""


def test_decrypt_with_primary_password_is_succesful(
    path_key4_primary_password, logins_with_primary_password, decrypted
):
    dec_username, dec_password = firefox.decrypt(
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
    dec_username, dec_password = firefox.decrypt(
        logins_with_primary_password.get("username"),
        logins_with_primary_password.get("password"),
        path_key4_primary_password,
        "BAD_PRIMARY_PASSWORD",
    )
    assert dec_username == ""
    assert dec_password == ""


def test_retrieve_master_key_is_succesful(path_key4):
    key, algorithm = firefox.retrieve_master_key(b"", path_key4)

    assert EncryptionAlgorithmId.map(algorithm) == "pbes2"
    assert key.hex() == "452c2f920285f794614af1c2d99ed331940d73298a526140"


@patch("dissect.target.helpers.apps.browser.firefox.decrypt_master_key", return_value=(b"", ""))
def test_retrieve_master_key_bad_password_check(mock_target, path_key4):
    key, algorithm = firefox.retrieve_master_key(b"", path_key4)
    assert key.hex() == ""
    assert algorithm == ""


@patch("dissect.target.helpers.apps.browser.firefox.query_master_key", return_value=(b"", ""))
def test_retrieve_master_key_no_master_key(mock_target, path_key4):
    key, algorithm = firefox.retrieve_master_key(b"", path_key4)
    assert key.hex() == ""
    assert algorithm == ""


@patch("dissect.target.helpers.apps.browser.firefox.query_master_key", return_value=(b"aaaa", "BAD_CKA_VALUE"))
def test_retrieve_master_key_bad_cka_value(mock_target, path_key4):
    key, algorithm = firefox.retrieve_master_key(b"", path_key4)
    assert key.hex() == ""
    assert algorithm == ""


def test_query_master_key(path_key4):
    master_key, master_key_cka = firefox.query_master_key(path_key4)

    assert isinstance(master_key, bytes)
    assert len(master_key) == 148

    assert isinstance(master_key_cka, bytes)
    assert len(master_key_cka) == 16
    assert master_key_cka == firefox.CKA_ID
