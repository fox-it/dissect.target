from pathlib import Path

import pytest

from dissect.target.helpers import keychain
from tests._utils import absolute_path


@pytest.fixture
def guarded_keychain():
    keychain.KEYCHAIN.clear()
    yield
    keychain.KEYCHAIN.clear()


def test_keychain_register_keychain_file(guarded_keychain):
    keychain_file = Path(absolute_path("_data/helpers/keychain/keychain.csv"))

    keychain.register_keychain_file(keychain_file)

    assert len(keychain.get_keys_without_provider()) == 1
    assert len(keychain.get_keys_for_provider("some")) == 0
    assert len(keychain.get_keys_for_provider("bitlocker")) == 2


def test_keychain_register_wildcard_value(guarded_keychain):
    keychain.register_wildcard_value("test-value")

    # Number of keys registered is equal number of supported key types, minus one for an invalid raw key
    assert len(keychain.get_keys_without_provider()) == len(keychain.KeyType) - 1

    keychain.KEYCHAIN.clear()
    keychain.register_wildcard_value("0000")

    # Valid raw key now included
    assert len(keychain.get_keys_without_provider()) == len(keychain.KeyType)
