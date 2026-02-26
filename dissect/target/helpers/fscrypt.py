from __future__ import annotations

import hashlib
import hmac
from typing import BinaryIO

from Crypto.Cipher import AES
from dissect.cstruct import cstruct
from dissect.fve.crypto import create_cipher
from dissect.util.stream import AlignedStream

from dissect.target.exceptions import FileDecryptionError

fscrypt_def = """
// https://github.com/torvalds/linux/blob/master/fs/crypto/fscrypt_private.h
#define HKDF_CONTEXT_KEY_IDENTIFIER	    1 /* info=<empty>		*/
#define HKDF_CONTEXT_PER_FILE_ENC_KEY	2 /* info=file_nonce		*/
#define HKDF_CONTEXT_DIRECT_KEY		    3 /* info=mode_num		*/
#define HKDF_CONTEXT_IV_INO_LBLK_64_KEY	4 /* info=mode_num||fs_uuid	*/
#define HKDF_CONTEXT_DIRHASH_KEY	    5 /* info=file_nonce		*/
#define HKDF_CONTEXT_IV_INO_LBLK_32_KEY	6 /* info=mode_num||fs_uuid	*/
#define HKDF_CONTEXT_INODE_HASH_KEY	    7 /* info=<empty */

#define FSCRYPT_POLICY_V1               0
#define FSCRYPT_KEY_DESCRIPTOR_SIZE     8
#define FSCRYPT_POLICY_V2               2
#define FSCRYPT_KEY_IDENTIFIER_SIZE     16
#define FSCRYPT_FILE_NONCE_SIZE	        16

/* Encryption algorithms */
#define FSCRYPT_MODE_AES_256_XTS		1
#define FSCRYPT_MODE_AES_256_CTS		4
#define FSCRYPT_MODE_AES_128_CBC		5
#define FSCRYPT_MODE_AES_128_CTS		6
#define FSCRYPT_MODE_SM4_XTS			7
#define FSCRYPT_MODE_SM4_CTS			8
#define FSCRYPT_MODE_ADIANTUM			9
#define FSCRYPT_MODE_AES_256_HCTR2		10

struct fscrypt_context_v1 {
    uint8 version; /* FSCRYPT_CONTEXT_V1 */
    uint8 contents_encryption_mode;
    uint8 filenames_encryption_mode;
    uint8 flags;
    char master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
    char nonce[FSCRYPT_FILE_NONCE_SIZE];
};

struct fscrypt_context_v2 {
    uint8 version; /* FSCRYPT_CONTEXT_V2 */
    uint8 contents_encryption_mode;
    uint8 filenames_encryption_mode;
    uint8 flags;
    uint8 log2_data_unit_size;
    uint8 __reserved[3];
    char master_key_identifier[FSCRYPT_KEY_IDENTIFIER_SIZE];
    char nonce[FSCRYPT_FILE_NONCE_SIZE];
};
"""

c_fscrypt = cstruct().load(fscrypt_def)
ZERO_BYTE_IV = b"\x00" * AES.block_size

# The final byte '01' is actually not part of the info but the block counter, which is always 1 for our purposes
FSCRYPT_IDENTIFIER_STR = b"fscrypt\0"
FSCRYPT_KEY_IDENTIFIER_INFO = (
    FSCRYPT_IDENTIFIER_STR + c_fscrypt.HKDF_CONTEXT_KEY_IDENTIFIER.to_bytes(1, "little") + b"\x01"
)


def fscrypt_hdkf(key: bytes, info_and_block_index: bytes) -> bytes:
    """Unsalted HKDF-SHA512 using a key and an info.

    We also ask the caller to pass a block index. Normally the hashing function should do that for the caller, but
    this allows the caller to pass a static info value that we don't have to concatonate another byte to every time
    this function is called."""
    hdkf_extracted_key = hmac.new(b"", key, hashlib.sha512).digest()
    hdkf_expand = hmac.new(hdkf_extracted_key, info_and_block_index, hashlib.sha512)
    return hdkf_expand.digest()


def fscrypt_key_identifier(key: bytes) -> str:
    """Derive a fscrypt-specific key identifier from a key."""
    return fscrypt_hdkf(key, FSCRYPT_KEY_IDENTIFIER_INFO)[: c_fscrypt.FSCRYPT_KEY_IDENTIFIER_SIZE].hex()


def aes_256_cts_cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES 256 with Ciphertext Stealing."""
    if len(ciphertext) <= 16:
        return AES.new(key, AES.MODE_ECB).decrypt(ciphertext)

    cipher = AES.new(key, AES.MODE_CBC, ZERO_BYTE_IV)

    # Round the ciphertext up to the next multiple of 16 and deduct 16
    last_block_start = ((len(ciphertext) + 15) & ~15) - 16
    second_to_last_block_start = last_block_start - 16

    # Put second-to-last block _behind_ the last block
    cts_ciphertext = ciphertext[last_block_start:]
    second_to_last_block = ciphertext[second_to_last_block_start:last_block_start]
    cts_ciphertext += second_to_last_block

    decrypted_prefix = cipher.decrypt(ciphertext[:second_to_last_block_start]) if last_block_start > 16 else b""
    return decrypted_prefix + cipher.decrypt(cts_ciphertext)


def aes_256_xts_decrypt(ciphertext: bytes, key: bytes, sector: int) -> bytes:
    """AES-XTS-256 decryption with a sector size of 4096."""
    return create_cipher("aes-xts-256", key, sector_size=4096, iv_sector_size=4096).decrypt(ciphertext, sector)


class FSCrypt:
    """FSCrypt decryption.

    The class can be given master keys.
    Then, for a given encyption context, if the associated master key is present, a combined key is derived and wrapped
    in an instance of the FSCryptEntryDecryptor class, that can use said key for filename and file contents decryption.

    Resources:
        - https://www.kernel.org/doc/html/v4.18/filesystems/fscrypt.html

    """

    def __init__(self, fh: BinaryIO):
        self.keys: dict[str, bytes] = {}
        self.fh = fh

    def add_key(self, key: bytes) -> None:
        self.keys[fscrypt_key_identifier(key)] = key

    def get_decryptor(self, encryption_context: bytes) -> FSCryptEntryDecryptor:
        encryption_context = c_fscrypt.fscrypt_context_v2(encryption_context)
        if encryption_context.version != c_fscrypt.FSCRYPT_POLICY_V2:
            raise NotImplementedError("Only FSCRYPT_POLICY_V2 is supported")
        master_key_identifier = encryption_context.master_key_identifier.hex()
        if master_key_identifier not in self.keys:
            raise FileDecryptionError("Requested key not found in keystore")
        master_key = self.keys[master_key_identifier]

        file_enc_info = (
            FSCRYPT_IDENTIFIER_STR
            + c_fscrypt.HKDF_CONTEXT_PER_FILE_ENC_KEY.to_bytes(1, "little")
            + encryption_context.nonce
        )
        file_enc_info += b"\01"  # Block counter
        derived_key = fscrypt_hdkf(master_key, file_enc_info)
        return FSCryptEntryDecryptor(self, encryption_context, derived_key)


class FSCryptEntryDecryptor:
    """Given an encryption context, and a derived key, can decrypt filenames and file contents."""

    def __init__(self, fscrypt: FSCrypt, encryption_context: c_fscrypt.fscrypt_context_v2, key: bytes):
        self.fscrypt = fscrypt
        self.encryption_context = encryption_context
        self.key = key

    def decrypt_filename(self, filename: bytes) -> bytes:
        if filename in [b".", b".."]:
            return filename
        if self.encryption_context.filenames_encryption_mode == c_fscrypt.FSCRYPT_MODE_AES_256_CTS:
            filename_key = self.key[0:32]
            ret = aes_256_cts_cbc_decrypt(filename, filename_key)
            return ret.rstrip(b"\0")

        raise NotImplementedError("Only FSCRYPT_MODE_AES_256_CTS is supported for filenames")

    def wrap_content_stream(self, runlist: tuple[int, int], size: int) -> XTSRunlistDecryptionStream:
        if self.encryption_context.contents_encryption_mode != c_fscrypt.FSCRYPT_MODE_AES_256_XTS:
            raise NotImplementedError("Only FSCRYPT_MODE_AES_256_XTS is supported for content streams")
        return XTSRunlistDecryptionStream(self.fscrypt.fh, self.key, runlist, size)


class XTSRunlistDecryptionStream(AlignedStream):
    """AES-XTS-256 decryption stream for a given runlist."""

    def __init__(
        self, fh: BinaryIO, key: bytes, runlist: list[tuple[int, int]], size: int | None = None, align: int = 4096
    ):
        self.fh = fh
        self.key = key
        self.runlist = runlist
        self._block_offsets: list[int] = None
        super().__init__(size, align)

    def _get_block_offsets(self) -> list[int]:
        if self._block_offsets is None:
            self._block_offsets = []
            for start, length in self.runlist:
                for i in range(length):
                    self._block_offsets.append(start + i)
        return self._block_offsets

    def _decrypt_block(self, block_index: int, offset: int) -> bytes:
        self.fh.seek(offset * self.align)
        encrypted = self.fh.read(self.align)
        return aes_256_xts_decrypt(encrypted, self.key, block_index)

    def _read(self, offset: int, length: int) -> bytes:
        r = []
        first_idx = offset // self.align
        last_idx = (first_idx + (length // self.align)) - 1
        for block_idx, block_offset in enumerate(self._get_block_offsets()):
            if block_idx < first_idx or block_idx > last_idx:
                continue
            r.append(self._decrypt_block(block_idx, block_offset))
        return b"".join(r)
