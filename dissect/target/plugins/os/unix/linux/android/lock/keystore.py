from __future__ import annotations

from typing import TYPE_CHECKING

from Crypto.Cipher import AES
from dissect.cstruct import cstruct
from dissect.database.sqlite3 import SQLite3

from dissect.target.plugin import InternalPlugin

if TYPE_CHECKING:
    from dissect.target.helpers.fsutil import TargetPath

keystore_def = """
// https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/sw_keyblob.rs
// KeyBlob::new_from_serialized
struct KeyBlob {
    uint8 version;
    uint32 key_material_length;
    char key_material[key_material_length];
    // In actuality KeyBlobs contain software- and hardware enforced parameters, including the encryption algorithm.
    // We do not use such fields and assume AES-256-GCM for all keys.
};
"""

PERSISTENT_KEYSTORE_PATH = "/data/misc/keystore/persistent.sqlite"
KEY_ENTRY_TABLE = "keyentry"

c_keystore = cstruct().load(keystore_def)


class KeystorePlugin(InternalPlugin):
    """The keystore is a system service that manages cryptographic keys and is used by Android's keychain API.
    It has two sorts of keys: persistent and per-boot.

    TODO: The Keystore is used by more than the synthetic password manager and fscrypt, but we only implemented it as
    far as needed for those two use cases. Expand functionality as needed.

    References:
    - https://developer.android.com/privacy-and-security/keystore
    - https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/database.rs
    - https://cs.android.com/android/platform/superproject/main/+/main:system/security/keystore2/src/sw_keyblob.rs
    - https://cs.android.com/android/platform/superproject/main/+/main:system/vold/KeyStorage.cpp

    """

    __namespace__ = "keystore"

    def check_compatible(self) -> None:
        # TODO: What would be a good compatibility check? Keystore functions are used for 'bootstrapping' the Android OS
        # plugin so a compatibility check on OS type cannot be performed when this plugin is initialized
        pass

    def get_persistent_keyblob(self, key: str) -> bytes:
        persistent_db = SQLite3(self.target.fs.get(PERSISTENT_KEYSTORE_PATH).open())

        key_entry_id = next(
            (row["id"] for row in persistent_db.table(KEY_ENTRY_TABLE).rows() if row["alias"] == key),
            None,
        )
        if key_entry_id is None:
            raise ValueError(f"Could not find {key} in persistent keystore")

        keyblob = next(
            (row["blob"] for row in persistent_db.table("blobentry") if row["keyentryid"] == key_entry_id),
            None,
        )
        if keyblob is None:
            raise ValueError(f"Entry was found in keystore for '{key}', but no associated blob was found")

        return keyblob

    @staticmethod
    def decrypt_blob(blob: bytes, key: bytes) -> bytes:
        nonce, ciphertext, auth_tag = blob[:12], blob[12:-16], blob[-16:]
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, auth_tag)

    @staticmethod
    def decrypt_key_from_keyblob(encrypted_key: bytes, keymaster_blob: bytes) -> bytes:
        keymaster = c_keystore.KeyBlob(keymaster_blob)
        return KeystorePlugin.decrypt_blob(encrypted_key, keymaster.key_material)

    @staticmethod
    def retrieve_key(path: TargetPath) -> bytes:
        encrypted_key = path.joinpath("encrypted_key")
        if not encrypted_key.exists():
            raise ValueError("encrypted_key not found in path")
        keymaster_blob = path.joinpath("keymaster_key_blob")
        if not keymaster_blob.exists():
            raise ValueError("keymaster_key_blob not found in path")
        return KeystorePlugin.decrypt_key_from_keyblob(encrypted_key.open().read(), keymaster_blob.open().read())
