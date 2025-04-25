from __future__ import annotations

import csv
import logging
from enum import Enum
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)


class KeyType(Enum):
    """Valid key types."""

    RAW = "raw"
    PASSPHRASE = "passphrase"
    RECOVERY_KEY = "recovery_key"
    FILE = "file"


class Key(NamedTuple):
    key_type: KeyType
    value: str | bytes
    provider: str | None = None
    identifier: str | None = None
    is_wildcard: bool = False


KEYCHAIN: list[Key] = []


def register_key(
    key_type: KeyType, value: str, identifier: str | None = None, provider: str | None = None, is_wildcard: bool = False
) -> None:
    if key_type == KeyType.RAW:
        try:
            value = bytes.fromhex(value)
        except ValueError:
            log.debug("Failed to decode raw key as hex, ignoring: %s", value)
            return

    if key_type in (KeyType.RECOVERY_KEY, KeyType.FILE):
        value = value.strip("\"'")

    key = Key(key_type, value, provider, identifier, is_wildcard)
    KEYCHAIN.append(key)
    log.info("Registered key %s", key)


def get_all_keys() -> list[Key]:
    return KEYCHAIN[:]


def get_keys_for_provider(provider: str) -> list[Key]:
    return [key for key in KEYCHAIN if key.provider and key.provider.lower() == provider.lower()]


def get_keys_without_provider() -> list[Key]:
    return [key for key in KEYCHAIN if not key.provider]


def parse_key_type(key_type_name: str) -> KeyType:
    for key_type in KeyType:
        if key_type.value == key_type_name:
            return key_type
    raise ValueError("No KeyType enum values that match %s", key_type_name)


def register_wildcard_value(value: str) -> None:
    for key_type in KeyType:
        register_key(key_type, value, is_wildcard=True)


def register_keychain_file(keychain_path: Path) -> None:
    """Register all keys from provided keychain file.

    The keychain file is a CSV file in "excel" dialect with the columns:

        provider,key_type,identifier,value

    Values in columns ``key_type`` and ``value`` are required, ``provider`` and ``identifier`` are optional.
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
            # Skip comment rows (starting with #)
            if row[0].startswith("#"):
                continue
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
