from __future__ import annotations

import hmac
import logging
import struct
from hashlib import sha256, sha512

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from dissect.cstruct import cstruct
from dissect.database.sqlite3 import SQLite3

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import keychain
from dissect.target.plugin import InternalPlugin

log = logging.getLogger(__name__)

synthetic_password_def = """
// https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java;

// PasswordData::fromBytes
struct PasswordData {
    uint16 credentialType_unused; // See fromBytes function for explanation why these two bytes must be ignored
	uint16 credentialType;
	uint8 scryptLogN;
	uint8 scryptLogR;
	uint8 scryptLogP;
	uint32 saltLen;
    char salt[saltLen];
	uint32 handleLen;
    char handle[handleLen];
};

// SyntheticPassword::fromBytes
struct SyntheticPasswordBlob {
    uint8 mVersion;
    uint8 mProtectorType;
    // Dynamic length and therefore not included:
    // byte[] mContent;
};
"""
c_synthetic_password = cstruct(endian=">").load(synthetic_password_def)

DEFAULT_SYNTHETIC_PASSWORD_CREDENTIALS = b"default-password".ljust(32, b"\x00")
SEC_DISCARDABLE_PREFIX = b"Android secdiscardable SHA512"
KEY_WRAPPING_PREFIX = b"Android key wrapping key generation SHA512"
PERSONALIZATION_FBE_KEY = b"fbe-key"
PERSONALIZATION_CONTEXT = b"android-synthetic-password-personalization-context"
PERSONALIZATION_SECDISCARDABLE = b"secdiscardable-transform"

SYNTHETIC_PASSWORD_VERSION_V3 = 3
PROTECTOR_TYPE_LSKF_BASED = 0

CREDENTIAL_ENCRYPTION_KEY_PATH = "/data/misc/vold/user_keys/ce/0/current"
SYNTHETIC_PASSWORD_BLOB_PATH = "/data/system_de/0/spblob"
LOCKSETTINGS_DB_PATH = "/data/system/locksettings.db"


def sp_800_derive(key: bytes, label: bytes, context: bytes) -> bytes:
    """Wraps a given key in a key-derivation function following Android's implementation of NIST SP 800-108.

    https://source.android.com/docs/security/features/encryption/hw-wrapped-keys
    https://android.googlesource.com/platform/frameworks/base/+/master/services/core/java/com/android/server/locksettings/SP800Derive.java
    """

    # As label and context are dynamic-size, struct.pack is more readable than some cstruct hacks
    counter = struct.pack(">I", 1)
    context_length = struct.pack(">I", len(context) * 8)
    output_length = struct.pack(">I", 256)
    sp_800_output = counter + label + b"\x00" + context + context_length + output_length
    out = hmac.new(key, digestmod=sha256)
    out.update(sp_800_output)
    return out.digest()


def personalized_hash(personalization: bytes, message: bytes) -> bytes:
    """Wrap a message in a SHA-512 hash with personalization."""
    digest = sha512(personalization.ljust(128, b"\x00"))
    digest.update(message)
    return digest.digest()


def decrypt_blob(blob: bytes, key: bytes) -> bytes:
    # Same method as keystore, but source code implements it seperately in the synthetic password manager
    nonce, ciphertext, auth_tag = blob[:12], blob[12:-16], blob[-16:]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, auth_tag)


class SyntheticPasswordManager(InternalPlugin):
    """A user's Synthetic Password (SP) never changes (as it is the main input for file-based encryption) but SP
    protectors can be added or removed. There must be at least one Lock-Screen Knowledge Factor (LSKF), though it may be
    'none' for an unprotected device. In such cases, a default value is used as an input for key derivation

    References:
        - https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java

    """

    __namespace__ = "synthetic_password_manager"

    def check_compatible(self) -> None:
        if not self.target.fs.path(LOCKSETTINGS_DB_PATH).exists():
            raise UnsupportedPluginError("Locksettings database not found")

    def decrypt_synthetic_password(self, sp_name: int) -> bytes:
        """Attempt to decrypt the SP using any available credentials in the keychain."""
        sp_name_zero_padded = f"{sp_name:016x}"
        sp_name = f"{sp_name:x}"

        sp_handle = self.target.fs.get(f"{SYNTHETIC_PASSWORD_BLOB_PATH}/{sp_name_zero_padded}.spblob").open()
        sp_blob = c_synthetic_password.SyntheticPasswordBlob(sp_handle)
        if sp_blob.mVersion != SYNTHETIC_PASSWORD_VERSION_V3:
            raise NotImplementedError("Only synthetic password version 3 is supported")
        if sp_blob.mProtectorType != PROTECTOR_TYPE_LSKF_BASED:
            raise NotImplementedError("Only LSKF based synthetic password is supported")
        twice_encrypted_synthetic_password = sp_handle.read()

        alias_in_keystore = f"synthetic_password_{sp_name}"
        synthetic_password_blob = self.target.keystore.get_persistent_keyblob(alias_in_keystore)
        once_encrypted_synthetic_password = self.target.keystore.decrypt_key_from_keyblob(
            twice_encrypted_synthetic_password, synthetic_password_blob
        )

        secdiscardable_transformed = personalized_hash(
            PERSONALIZATION_SECDISCARDABLE,
            self.target.fs.get(f"{SYNTHETIC_PASSWORD_BLOB_PATH}/{sp_name_zero_padded}.secdis").open().read(),
        )

        pwd_path = next(self.target.fs.path(SYNTHETIC_PASSWORD_BLOB_PATH).glob("*.pwd"), None)
        if pwd_path is None:
            # Synthetic Password is not protected by a user-credential
            passwords = [(DEFAULT_SYNTHETIC_PASSWORD_CREDENTIALS, DEFAULT_SYNTHETIC_PASSWORD_CREDENTIALS)]
        else:
            password_data = c_synthetic_password.PasswordData(pwd_path.open().read())
            passwords = []
            for key in keychain.get_keys_for_provider("android") + keychain.get_keys_without_provider():
                if key.key_type == keychain.KeyType.PASSPHRASE:
                    passwords.append(
                        (
                            key.value,
                            scrypt(
                                key.value,
                                password_data.salt,
                                32,
                                1 << password_data.scryptLogN,
                                1 << password_data.scryptLogR,
                                1 << password_data.scryptLogP,
                            ),
                        )
                    )

        if len(passwords) == 0:
            raise ValueError("Cannot decrypt credential-encrypted storage without a (derived) password")
        for plaintext_password, encrypted_password in passwords:
            inner_key = personalized_hash(b"application-id", encrypted_password + secdiscardable_transformed)[:32]
            try:
                decrypted_key = decrypt_blob(once_encrypted_synthetic_password, inner_key)
                # TODO: For reviewer: logging the plaintext password that ended up working _can_ be useful but also
                # undesireable. Ideally this would be configurable
                logging.info("Decrypted credential-encrypted storage with password '%s'", plaintext_password)
            except Exception:
                pass
            else:
                return decrypted_key
        raise ValueError(f"Failed to decrypt credential-encrypted storage, tried {len(passwords)} password(s).")

    def get_credential_encryption_key(self) -> bytes:
        """Get the credential encryption key from the device."""
        encrypted_credential_encryption_key_path = self.target.fs.path(CREDENTIAL_ENCRYPTION_KEY_PATH)
        locksettings_db = SQLite3(self.target.fs.get(LOCKSETTINGS_DB_PATH).open())
        sp_handle = next(
            (row.value for row in locksettings_db.table("locksettings").rows() if row.name == "sp-handle"), None
        )

        if sp_handle is None:
            # The credential encryption key is only encrypted using the keymaster file in the same directory
            # This is only the case for old Android versions
            return self.target.keystore.retrieve_key(encrypted_credential_encryption_key_path)

        # 64-bit boundary
        sp_name = int(sp_handle) & 0xFFFFFFFFFFFFFFFF

        # The CE key is encrypted using a wrapped key derived from the synthetic password
        encrypted_credential_encryption_key = (
            encrypted_credential_encryption_key_path.joinpath("encrypted_key").open().read()
        )

        # Every user has one synthetic password, which may be protected by any number of spblobs
        # This is the part that might require a Lock-Screen Knowledge Factor (LSKF) if the device is protected
        synthetic_password = self.decrypt_synthetic_password(sp_name)

        # Derive a key from the synthetic password that is used by fscrypt
        sp_800_derived_pw = sp_800_derive(synthetic_password, PERSONALIZATION_FBE_KEY, PERSONALIZATION_CONTEXT)
        wrapped_pw = personalized_hash(KEY_WRAPPING_PREFIX, sp_800_derived_pw)[:32]

        # The final key to be used for fscrypt
        return decrypt_blob(encrypted_credential_encryption_key, wrapped_pw)
