"""Decryption algorithms for Firefox.

Resources:
    - https://github.com/lclevy/firepwd
"""

import hmac
import logging
from base64 import b64decode
from hashlib import pbkdf2_hmac, sha1

from asn1crypto import algos, core
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import unpad
from dissect.sql import sqlite3

from dissect.target.helpers.fsutil import TargetPath

log = logging.getLogger(__name__)

# Define separately because it is not defined in asn1crypto
pbeWithSha1AndTripleDES_CBC = "1.2.840.113549.1.12.5.1.3"
CKA_ID = b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"


def decrypt_moz_3des(global_salt: bytes, primary_password: bytes, entry_salt: str, encrypted: bytes) -> bytes:
    hp = sha1(global_salt + primary_password).digest()
    pes = entry_salt + b"\x00" * (20 - len(entry_salt))
    chp = sha1(hp + entry_salt).digest()
    k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encrypted)


def decode_login_data(data: str) -> tuple[bytes, bytes, bytes]:
    """
    SEQUENCE {
        KEY_ID
        SEQUENCE {
            OBJECT_IDENTIFIER
            IV
        }
        CIPHERTEXT
    }
    """
    decoded = core.load(b64decode(data))
    key_id = decoded[0].native
    iv = decoded[1][1].native
    ciphertext = decoded[2].native
    return key_id, iv, ciphertext


def decrypt_pbes2(decoded_item: list, primary_password: bytes, global_salt) -> bytes:
    """
    SEQUENCE {
      SEQUENCE {
        OBJECTIDENTIFIER 1.2.840.113549.1.5.13 => pkcs5 pbes2
        SEQUENCE {
          SEQUENCE {
            OBJECTIDENTIFIER 1.2.840.113549.1.5.12 => pbkdf2
            SEQUENCE {
              OCTETSTRING 32 bytes, entrySalt
              INTEGER 01
              INTEGER 20
              SEQUENCE {
                OBJECTIDENTIFIER 1.2.840.113549.2.9 => hmacWithSHA256
              }
            }
          }
          SEQUENCE {
            OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 => aes256-CBC
            OCTETSTRING 14 bytes, iv
          }
        }
      }
      OCTETSTRING encrypted
    }
    """

    pkcs5_oid = decoded_item[0][1][0][0].dotted
    if algos.KdfAlgorithmId.map(pkcs5_oid) != "pbkdf2":
        raise ValueError(f"Expected pbkdf2 object identifier, got: {pkcs5_oid}")

    sha256_oid = decoded_item[0][1][0][1][3][0].dotted
    if algos.HmacAlgorithmId.map(sha256_oid) != "sha256":
        raise ValueError(f"Expected SHA256 object identifier, got: {pkcs5_oid}")

    aes256_cbc_oid = decoded_item[0][1][1][0].dotted
    if algos.EncryptionAlgorithmId.map(aes256_cbc_oid) != "aes256_cbc":
        raise ValueError(f"Expected AES256-CBC object identifier, got: {pkcs5_oid}")

    entry_salt = decoded_item[0][1][0][1][0].native
    iteration_count = decoded_item[0][1][0][1][1].native
    key_length = decoded_item[0][1][0][1][2].native

    if key_length != 32:
        raise ValueError(f"Expected key_length to be 32, got: {key_length}")

    k = sha1(global_salt + primary_password).digest()
    key = pbkdf2_hmac("sha256", k, entry_salt, iteration_count, dklen=key_length)

    iv = b"\x04\x0e" + decoded_item[0][1][1][1].native
    cipher_text = decoded_item[1].native
    return AES.new(key, AES.MODE_CBC, iv).decrypt(cipher_text)


def decrypt_sha1_triple_des_cbc(decoded_item: core.Sequence, primary_password: bytes, global_salt: bytes) -> bytes:
    """
    SEQUENCE {
        SEQUENCE {
            OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
            SEQUENCE {
                OCTETSTRING entry_salt
                INTEGER 01
            }
        }
        OCTETSTRING encrypted
    }
    """
    entry_salt = decoded_item[0][1][0].native
    cipher_text = decoded_item[1].native
    key = decrypt_moz_3des(global_salt, primary_password, entry_salt, cipher_text)
    return key[:24]


def decrypt_master_key(decoded_item: core.Sequence, primary_password: bytes, global_salt: bytes) -> tuple[bytes, str]:
    """At this stage, we're not yet sure of the structure of decoded_item.

    The structure will depend on the object identifier at [0][0], hence we extract it.

    SEQUENCE {
        SEQUENCE {
            OBJECTIDENTIFIER ???
            ...
        }
        ...
    }
    """
    object_identifier = decoded_item[0][0]
    algorithm = object_identifier.dotted

    if algos.EncryptionAlgorithmId.map(algorithm) == "pbes2":
        return decrypt_pbes2(decoded_item, primary_password, global_salt), algorithm
    elif algorithm == pbeWithSha1AndTripleDES_CBC:
        return decrypt_sha1_triple_des_cbc(decoded_item, primary_password, global_salt), algorithm
    else:
        # Firefox supports other algorithms (i.e. Firefox published before 2018),
        # but decrypting these are not (yet) supported.
        return b"", algorithm


def query_global_salt(key4_file: TargetPath) -> tuple[str, str]:
    db = sqlite3.SQLite3(key4_file.open())
    metadata = db.table("metadata").rows()
    for row in metadata:
        if row.get("id") == "password":
            return row.get("item1", ""), row.get("item2", "")


def query_master_key(key4_file: TargetPath) -> tuple[str, str]:
    db = sqlite3.SQLite3(key4_file.open())
    metadata = db.table("nssPrivate").rows()
    for row in metadata:
        return row.get("a11", ""), row.get("a102", "")


def retrieve_master_key(primary_password: bytes, key4_file: TargetPath) -> tuple[bytes, str]:
    global_salt, password_check = query_global_salt(key4_file)
    decoded_password_check = core.load(password_check)
    decrypted_password_check, algorithm = decrypt_master_key(decoded_password_check, primary_password, global_salt)

    if not decrypted_password_check:
        log.warning(f"Encountered unknown algorithm {algorithm} while decrypting master key.")
        return b"", ""

    expected_password_check = b"password-check\x02\x02"
    if decrypted_password_check != b"password-check\x02\x02":
        log.warning(
            "Master key decryption failed. Either the master key is protected by a "
            "primary password which you did not supply, or the primary password you provided was incorrect."
        )
        log.debug(f"Expected {expected_password_check} but got {decrypted_password_check}")
        return b"", ""

    master_key, master_key_cka = query_master_key(key4_file)
    if master_key == b"":
        log.warning("Password master key is not defined.")
        return b"", ""

    if master_key_cka != CKA_ID:
        log.warning(f"Password master key cka '{master_key_cka}' is not equal to expected value '{CKA_ID}'.")
        return b"", ""

    decoded_master_key = core.load(master_key)
    decrypted, algorithm = decrypt_master_key(decoded_master_key, primary_password, global_salt)
    return decrypted[:24], algorithm


def decrypt_field(key: bytes, field: tuple[bytes, bytes, bytes]) -> bytes:
    cka, iv, ciphertext = field

    if cka != CKA_ID:
        raise ValueError(f"Expected cka to equal '{CKA_ID}' but got '{cka}'")

    return unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8)


def decrypt(username: str, password: str, key4_file: TargetPath, primary_password: str = "") -> tuple[str, str]:
    try:
        username = decode_login_data(username)
        password = decode_login_data(password)

        primary_password_bytes = primary_password.encode()
        key, algorithm = retrieve_master_key(primary_password_bytes, key4_file)

        if not key or not algorithm:
            return "", ""

        if algorithm == pbeWithSha1AndTripleDES_CBC or algos.EncryptionAlgorithmId.map(algorithm) == "pbes2":
            username = decrypt_field(key, username)
            password = decrypt_field(key, password)
            return username.decode(), password.decode()
    except ValueError as e:
        log.error("Failed to decrypt encrypted password", exc_info=e)
    return "", ""
