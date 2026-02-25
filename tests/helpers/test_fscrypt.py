import hashlib

import pytest

from dissect.target.exceptions import FileDecryptionError
from dissect.target.helpers.fscrypt import FSCrypt, FSCryptEntryDecryptor, c_fscrypt, fscrypt_key_identifier
from tests._utils import absolute_path

FILESYSTEM_MASTER_KEY = bytes.fromhex(
    "98866cabd76ab14358ec324f7f217da0e063824919ed0fffaa4c9c415dbc74d3496811cc68f8997294e5b7741d7c3e7a646317d37af77b170e4f4b3c27dd978f"
)

MASTER_KEY_IDENTIFIER = b"\x9eZ\xde\x06?f\x0c\xd5\x02\xf2zJ\x98\x90\x01X"

ENCRYPTED_DIRECTORY_ENCRYPTION_CONTEXT = c_fscrypt.fscrypt_context_v2(
    version=0x2,
    contents_encryption_mode=0x1,
    filenames_encryption_mode=0x4,
    flags=0x2,
    log2_data_unit_size=0x0,
    __reserved=b"\x00\x00\x00",
    master_key_identifier=MASTER_KEY_IDENTIFIER,
    nonce=b"\xb5g\x19\xe6>\xfc+K'\xfd\xea\\\xc9pH\xc8",
)

ENCRYPTED_DIRECTORY_EXPECTED_DERIVED_KEY = bytes.fromhex(
    "ba352926cdde93a0bdb6886991a1570fa659a8d36773e977378b98efbbdb816a90d8e11017b1cadf20ff2608a03b55368b3e8da986ab5c3011c95a59f651ab9e"
)

ENCRYPTED_FILE_ENCYRPTION_CONTEXT = c_fscrypt.fscrypt_context_v2(
    version=0x2,
    contents_encryption_mode=0x1,
    filenames_encryption_mode=0x4,
    flags=0x2,
    log2_data_unit_size=0x0,
    __reserved=b"\x00\x00\x00",
    master_key_identifier=MASTER_KEY_IDENTIFIER,
    nonce=b"\xe2|\x07GT\r\xab\x8duc0\x89k\x7f2\x9b",
)

ENCRYPTED_FILE_EXPECTED_DERIVED_KEY = bytes.fromhex(
    "6e61113c6cdfa174484593be20c5319895ab3a370a5a438a3e722e2e934008682b3af28b3b61fe00c78564c1a6bdfa1a7dbcb966b1194ae35655f9ca4c99639e"
)

ENCRYPTED_FILE_SIZE = 85622
ENCRYPTED_FILE_NUM_BLOCKS = 21


def test_fscrypt_key_identifier() -> None:
    assert fscrypt_key_identifier(FILESYSTEM_MASTER_KEY) == MASTER_KEY_IDENTIFIER.hex()


def test_decrypt_directory_filenames() -> None:
    fscrypt = FSCrypt(None)
    decryptor = FSCryptEntryDecryptor(
        fscrypt, ENCRYPTED_DIRECTORY_ENCRYPTION_CONTEXT, ENCRYPTED_DIRECTORY_EXPECTED_DERIVED_KEY
    )

    assert (
        decryptor.decrypt_filename(
            b"\xc4u\x9c\xb1\xf4\x16M\xad\xa8N\x98\xc6\xfdAh\x1c\x1c\xf4+F\x0e;\x10s\xe7\x12b\xb0\xba\x9d\xd8S\xd4J\xf9\xc0E\x1d\x05sKJ.\xc9\xad'\xa9\xd4"
        )
        == b"but-there-are-so-many-routes-to-take.jpg"
    )

    assert decryptor.decrypt_filename(b"\x93\x13svT:\xc5\x9d\x1c\xde\xc85\x14\xd1\xeeF") == b"short.filename"
    assert decryptor.decrypt_filename(b".") == b"."
    assert decryptor.decrypt_filename(b"..") == b".."


def test_fscrypt_get_decryptor() -> None:
    fscrypt = FSCrypt(None)
    with pytest.raises(FileDecryptionError):
        fscrypt.get_decryptor(ENCRYPTED_DIRECTORY_ENCRYPTION_CONTEXT.dumps())
    fscrypt.add_key(FILESYSTEM_MASTER_KEY)
    decryptor = fscrypt.get_decryptor(ENCRYPTED_DIRECTORY_ENCRYPTION_CONTEXT.dumps())
    decryptor.key = ENCRYPTED_DIRECTORY_EXPECTED_DERIVED_KEY


def test_xts_runlist_decryption_stream() -> None:
    runlist = [(0, ENCRYPTED_FILE_NUM_BLOCKS)]

    fscrypt = FSCrypt(None)
    fscrypt.add_key(FILESYSTEM_MASTER_KEY)
    decryptor = fscrypt.get_decryptor(ENCRYPTED_FILE_ENCYRPTION_CONTEXT.dumps())

    decrypted_stream = decryptor.wrap_content_stream(runlist, ENCRYPTED_FILE_SIZE)

    # Nonce + Master key
    assert decrypted_stream.key == ENCRYPTED_FILE_EXPECTED_DERIVED_KEY

    with absolute_path("_data/helpers/fscrypt/encrypted.jpg").open("rb") as fh:
        decrypted_stream.fh = fh
        decrypted_stream.seek(0)

        # Should be a jpeg
        assert decrypted_stream.read(10) == b"\xff\xd8\xff\xe0\x00\x10JFIF"
        decrypted_stream.seek(0)
        full_stream = decrypted_stream.read()
        assert hashlib.md5(full_stream).hexdigest() == "325f72e4c6d8177d2a7cbcf3cb01f30f"
