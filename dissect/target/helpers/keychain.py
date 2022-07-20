import csv
import logging
from enum import Enum
from pathlib import Path
from typing import Set, NamedTuple, List


log = logging.getLogger(__name__)


class KeyType(Enum):
    PASSPHRASE = "passphrase"
    RECOVERY_KEY = "recovery_key"
    FILE = "file"


class Key(NamedTuple):
    key_type: KeyType
    value: str
    provider: str = None
    identifier: str = None


KEYCHAIN: Set[Key] = set()


def register_key(key_type: KeyType, value: str, identifier: str = None, provider: str = None):
    key = Key(provider=provider, key_type=key_type, value=value, identifier=identifier)
    KEYCHAIN.add(key)
    log.info("Registered key %s", key)


def get_all_keys() -> List[Key]:
    return list(KEYCHAIN)


def get_keys_for_provider(provider: str) -> List[Key]:
    return [key for key in KEYCHAIN if key.provider and key.provider.lower() == provider.lower()]


def get_keys_without_provider() -> List[Key]:
    return [key for key in KEYCHAIN if not key.provider]


def parse_key_type(key_type_name: str) -> KeyType:
    for key_type in KeyType:
        if key_type.value == key_type_name:
            return key_type
    raise ValueError("No KeyType enum values that match %s", key_type_name)


def register_wildcard_value(value: str):
    for key_type in KeyType:
        register_key(key_type=key_type, value=value)


def register_keychain_file(keychain_path: Path):
    """Register all keys from provided keychain file.

    The keychain file is a CSV file in "excel" dialect with the columns:

        provider,key_type,identifier,value

    Values in columns `key_type` and `value` are required, `provider` and `identifier` are optional.
    Example of the CSV-serialised data:

        bitlocker,recovery_key,,312268-409816-583517-486695-627121-599511-664389-145640
        bitlocker,passphrase,,Password1234
        ,passphrase,,AnotherTestPassword
        bitlocker,passphrase,b6ad258a-2725-4a42-93c6-844478bf7a90,Password1234
        bitlocker,passphrase,,"Password with comma, space and quotes ' and "" inside"
    """
    if not keychain_path.exists():
        raise ValueError("Provided keychain file %s does not exists", keychain_path)

    with keychain_path.open(mode="r") as fh:
        rows = csv.reader(fh)
        for row in rows:
            if len(row) != 4:
                log.warning("Expecting 4 values per row in a keychain CSV file, found %d: %s. Skipping", len(row), row)
                continue

            provider, key_type_name, identifier, value = row
            try:
                key_type = parse_key_type(key_type_name)
            except ValueError:
                log.warning("Unrecognised key type %s", key_type_name)
                continue

            if not value:
                log.warning("No value provided in row %s", row)
                continue

            identifier = identifier if identifier else None
            provider = provider if provider else None

            register_key(
                key_type=key_type,
                value=value,
                identifier=identifier,
                provider=provider,
            )
