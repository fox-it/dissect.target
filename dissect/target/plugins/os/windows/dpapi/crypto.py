from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

try:
    from Crypto.Cipher import AES, ARC4, DES3

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

CIPHER_ALGORITHMS: dict[int | str, CipherAlgorithm] = {}
HASH_ALGORITHMS: dict[int | str, HashAlgorithm] = {}

if TYPE_CHECKING:
    from typing_extensions import Self


class CipherAlgorithm:
    id: int
    name: str
    key_length: int
    iv_length: int
    block_length: int

    def __init_subclass__(cls):
        CIPHER_ALGORITHMS[cls.id] = cls
        CIPHER_ALGORITHMS[cls.name] = cls

    @classmethod
    def from_id(cls, id: int) -> Self:
        return CIPHER_ALGORITHMS[id]()

    @classmethod
    def from_name(cls, name: str) -> Self:
        return CIPHER_ALGORITHMS[name]()

    def derive_key(self, key: bytes, hash_algorithm: HashAlgorithm) -> bytes:
        """Mimics the corresponding native Microsoft function.

        Resources:
            - https://github.com/tijldeneut/DPAPIck3/blob/main/dpapick3/crypto.py#L185
        """

        if len(key) > hash_algorithm.block_length:
            key = hashlib.new(hash_algorithm.name, key).digest()

        if len(key) >= self.key_length:
            return key

        key = key.ljust(hash_algorithm.block_length, b"\x00")
        pad1 = bytes(c ^ 0x36 for c in key)[: hash_algorithm.block_length]
        pad2 = bytes(c ^ 0x5C for c in key)[: hash_algorithm.block_length]
        key = hashlib.new(hash_algorithm.name, pad1).digest() + hashlib.new(hash_algorithm.name, pad2).digest()
        return self.fixup_key(key)

    def fixup_key(self, key: bytes) -> bytes:
        return key

    def decrypt_with_hmac(
        self, data: bytes, key: bytes, iv: bytes, hash_algorithm: HashAlgorithm, rounds: int
    ) -> bytes:
        derived = pbkdf2(key, iv, self.key_length + self.iv_length, rounds, hash_algorithm.name)
        key, iv = derived[: self.key_length], derived[self.key_length :]

        return self.decrypt(data, key, iv)

    def decrypt(self, data: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        raise NotImplementedError


class _AES(CipherAlgorithm):
    id = 0x6611
    name = "AES"
    key_length = 128 // 8
    iv_length = 128 // 8
    block_length = 128 // 8

    def decrypt(self, data: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if not HAS_CRYPTO:
            raise RuntimeError("Missing pycryptodome dependency")

        cipher = AES.new(
            key[: self.key_length], mode=AES.MODE_CBC, IV=iv[: self.iv_length] if iv else b"\x00" * self.iv_length
        )
        return cipher.decrypt(data)


class _AES128(_AES):
    id = 0x660E
    name = "AES-128"


class _AES192(_AES):
    id = 0x660F
    name = "AES-192"
    key_length = 192 // 8


class _AES256(_AES):
    id = 0x6610
    name = "AES-256"
    key_length = 256 // 8


class _RC4(CipherAlgorithm):
    id = 0x6801
    name = "RC4"
    key_length = 40 // 8
    iv_length = 128 // 8
    block_length = 1 // 8

    def decrypt(self, data: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if not HAS_CRYPTO:
            raise RuntimeError("Missing pycryptodome dependency")

        cipher = ARC4.new(key[: self.key_length])
        return cipher.decrypt(data)


class _DES3(CipherAlgorithm):
    id = 0x6603
    name = "DES3"
    key_length = 192 // 8
    iv_length = 64 // 8
    block_length = 64 // 8

    def fixup_key(self, key: bytes) -> bytes:
        nkey = []
        for byte in key:
            parity_bit = 0
            for i in range(8):
                parity_bit ^= (byte >> i) & 1

            nkey.append(byte if parity_bit == 0 else byte | 1)
        return bytes(nkey[: self.key_length])

    def decrypt(self, data: bytes, key: bytes, iv: bytes | None = None) -> bytes:
        if not HAS_CRYPTO:
            raise RuntimeError("Missing pycryptodome dependency")

        if len(key) != 24:
            raise ValueError(f"Invalid DES3 CBC key length {len(key)}")

        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv if iv else b"\x00" * 8)
        return cipher.decrypt(data)


class HashAlgorithm:
    id: int
    name: str
    digest_length: int
    block_length: int

    def __init_subclass__(cls):
        HASH_ALGORITHMS[cls.id] = cls
        HASH_ALGORITHMS[cls.name] = cls

    @classmethod
    def from_id(cls, id: int) -> Self:
        return HASH_ALGORITHMS[id]()

    @classmethod
    def from_name(cls, name: str) -> Self:
        return HASH_ALGORITHMS[name]()


class _MD5(HashAlgorithm):
    id = 0x8003
    name = "md5"
    digest_length = 128 // 8
    block_length = 512 // 8


class _SHA1(HashAlgorithm):
    id = 0x8004
    name = "sha1"
    digest_length = 160 // 8
    block_length = 512 // 8


class _HMAC(_SHA1):
    """Synonymous to SHA1."""

    id = 0x8009


class _SHA256(HashAlgorithm):
    id = 0x800C
    name = "sha256"
    digest_length = 256 // 8
    block_length = 512 // 8


class _SHA384(HashAlgorithm):
    id = 0x800D
    name = "sha384"
    digest_length = 384 // 8
    block_length = 1024 // 8


class _SHA512(HashAlgorithm):
    id = 0x800E
    name = "sha512"
    digest_length = 512 // 8
    block_length = 1024 // 8


def pbkdf2(passphrase: bytes, salt: bytes, key_len: int, iterations: int, digest: str = "sha1") -> bytes:
    """Implementation of PBKDF2 that allows specifying digest algorithm.

    Returns the corresponding expanded key which is ``key_len`` long.
    """
    key = bytearray()

    i = 1
    while len(key) < key_len:
        U = salt + i.to_bytes(4, "big")
        i += 1

        derived = hmac.new(passphrase, U, digestmod=digest).digest()
        for _ in range(iterations - 1):
            actual = hmac.new(passphrase, derived, digestmod=digest).digest()
            derived = bytes(x ^ y for x, y in zip(derived, actual))
        key.extend(derived)

    return bytes(key[:key_len])


def dpapi_hmac(pwd_hash: bytes, hmac_salt: bytes, value: bytes, hash_algorithm: HashAlgorithm) -> bytes:
    """Internal function used to compute HMACs of DPAPI structures."""
    key = hmac.new(pwd_hash, hmac_salt, digestmod=hash_algorithm.name).digest()
    return hmac.new(key, value, digestmod=hash_algorithm.name).digest()


def crypt_session_key_type1(
    master_key: bytes,
    nonce: bytes | None,
    hash_algorithm: HashAlgorithm,
    entropy: bytes | None = None,
    strong_password: str | None = None,
    smart_card_secret: bytes | None = None,
    verify_blob: bytes | None = None,
) -> bytes:
    """Computes the decryption key for Type1 DPAPI blob, given the master key and optional information.

    This implementation relies on a faulty implementation from Microsoft that does not respect the HMAC RFC.
    Instead of updating the inner pad, we update the outer pad.
    This algorithm is also used when checking the HMAC for integrity after decryption.

    Args:
        master_key: Decrypted master key (should be 64 bytes long).
        nonce: This is the nonce contained in the blob or the HMAC in the blob (integrity check).
        hash_algorithm: A :class:`HashAlgorithm` to use for calculating block sizes.
        entropy: This is the optional entropy from ``CryptProtectData()`` API.
        strong_password: Optional password used for decryption or the blob itself.
        smart_card_secret: Optional MS Next Gen Crypto secret (e.g. from PIN code).
        verify_blob: Optional encrypted blob used for integrity check.

    Returns:
        The decryption key.
    """
    if len(master_key) > 20:
        master_key = hashlib.sha1(master_key).digest()

    master_key = master_key.ljust(hash_algorithm.block_length, b"\x00")
    pad1 = bytes(c ^ 0x36 for c in master_key)
    pad2 = bytes(c ^ 0x5C for c in master_key)

    digest1 = hashlib.new(hash_algorithm.name)
    digest1.update(pad2)

    digest2 = hashlib.new(hash_algorithm.name)
    digest2.update(pad1)
    digest2.update(nonce)

    if entropy and smart_card_secret:
        digest2.update(entropy + smart_card_secret)
        if verify_blob:
            digest2.update(verify_blob)

    digest1.update(digest2.digest())
    if entropy and not smart_card_secret:
        digest1.update(entropy)

    if strong_password:
        strong_password = hashlib.sha1(strong_password.rstrip("\x00").encode("utf-16-le")).digest()
        digest1.update(strong_password)

    if verify_blob and not smart_card_secret:
        digest1.update(verify_blob)

    return digest1.digest()


def crypt_session_key_type2(
    masterkey: bytes,
    nonce: bytes,
    hash_algorithm: HashAlgorithm,
    entropy: bytes | None = None,
    strong_password: str | None = None,
    smart_card_secret: bytes | None = None,
    verify_blob: bytes | None = None,
) -> bytes:
    """Computes the decryption key for Type2 DPAPI blob, given the masterkey and optional information.

    This implementation relies on an RFC compliant HMAC implementation.
    This algorithm is also used when checking the HMAC for integrity after decryption.

    Args:
        master_key: Decrypted master key (should be 64 bytes long).
        nonce: This is the nonce contained in the blob or the HMAC in the blob (integrity check).
        hash_algo: A :class:`HashAlgorithm` to use for calculating block sizes.
        entropy: This is the optional entropy from ``CryptProtectData()`` API.
        strong_password: Optional password used for decryption or the blob itself.
        smart_card_secret: Optional MS Next Gen Crypto secret (e.g. from PIN code). Only for API compatibility.
        verify_blob: Optional encrypted blob used for integrity check.

    Returns:
        The decryption key.
    """
    if len(masterkey) > 20:
        masterkey = hashlib.sha1(masterkey).digest()

    digest = hmac.new(masterkey, digestmod=hash_algorithm.name)
    digest.update(nonce)

    if entropy:
        digest.update(entropy)

    if strong_password:
        strong_password = hashlib.sha512(strong_password.rstrip("\x00").encode("utf-16-le")).digest()
        digest.update(strong_password)

    elif verify_blob:
        digest.update(verify_blob)

    return digest.digest()


def derive_password_hash(password_hash: bytes, user_sid: str, digest: str = "sha1") -> bytes:
    """Internal use. Computes the encryption key from a user's password hash."""
    return hmac.new(password_hash, (user_sid + "\0").encode("utf-16-le"), digestmod=digest).digest()
