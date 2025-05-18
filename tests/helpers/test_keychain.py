from __future__ import annotations

from pathlib import Path

from dissect.target.helpers import keychain
from tests._utils import absolute_path


def test_keychain_register_keychain_file(guarded_keychain: None) -> None:
    keychain_file = Path(absolute_path("_data/helpers/keychain/keychain.csv"))

    keychain.register_keychain_file(keychain_file)

    assert len(keychain.get_keys_without_provider()) == 1
    assert len(keychain.get_keys_for_provider("some")) == 0
    assert len(keychain.get_keys_for_provider("bitlocker")) == 2


def test_keychain_register_wildcard_value(guarded_keychain: None) -> None:
    keychain.register_wildcard_value("test-value")

    # Number of keys registered is equal number of supported key types, minus one for an invalid raw key
    assert len(keychain.get_keys_without_provider()) == len(keychain.KeyType) - 1

    keychain.KEYCHAIN.clear()
    keychain.register_wildcard_value("0000")

    # Valid raw key now included
    assert len(keychain.get_keys_without_provider()) == len(keychain.KeyType)

    keychain.KEYCHAIN.clear()
    keychain.register_wildcard_value("'312268-409816-583517-486695-627121-599511-664389-145640'")
    for key in keychain.get_all_keys():
        if key.key_type in (keychain.KeyType.RECOVERY_KEY, keychain.KeyType.FILE):
            assert key.value == "312268-409816-583517-486695-627121-599511-664389-145640"
