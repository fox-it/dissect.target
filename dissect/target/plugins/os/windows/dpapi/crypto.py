from __future__ import annotations

import hashlib
import hmac
import struct
from abc import ABC, abstractproperty
from types import ModuleType
from typing import Optional

from Crypto.Cipher import AES, ARC4

CIPHER_ALGORITHMS: dict[id, CipherAlgorithm] = {}
HASH_ALGORITHMS: dict[id, HashAlgorithm] = {}


class CipherAlgorithm(ABC):
    id: int
    name: str
    key_length: int
    iv_length: int
    block_length: int
    cipher_module: ModuleType

    def __init_subclass__(cls):
        CIPHER_ALGORITHMS[cls.id] = cls

    @classmethod
    def from_id(cls, id: int) -> CipherAlgorithm:
        return CIPHER_ALGORITHMS[id]()

    def fixup_key(self, key: bytes) -> bytes:
        return key

    def derive_key(self, key: bytes, hash_algorithm: HashAlgorithm) -> bytes:
        """Mimics the corresponding native Microsoft function"""
        if len(key) > hash_algorithm.block_length:
            key = hashlib.new(hash_algorithm.name, key).digest()
        if len(key) >= hash_algorithm.digest_length:
            return key
        key += b"\x00" * hash_algorithm.block_length
        pad1 = "".join(chr(key[i] ^ 0x36) for i in range(hash_algorithm.block_length))
        pad2 = "".join(chr(key[i] ^ 0x5C) for i in range(hash_algorithm.block_length))
        k = (
            hashlib.new(hash_algorithm.name, pad1.encode("latin1")).digest()
            + hashlib.new(hash_algorithm.name, pad2.encode("latin1")).digest()
        )
        return self.fixup_key(k)

    @property
    @abstractproperty
    def id(self):
        raise NotImplementedError

    @property
    @abstractproperty
    def name(self):
        raise NotImplementedError

    @property
    @abstractproperty
    def key_length(self):
        raise NotImplementedError

    @property
    @abstractproperty
    def iv_length(self):
        raise NotImplementedError

    @property
    @abstractproperty
    def block_length(self):
        raise NotImplementedError

    @property
    @abstractproperty
    def cipher_module(self):
        raise NotImplementedError

    def decrypt_with_hmac(
        self, data: bytes, key: bytes, iv: bytes, hash_algorithm: HashAlgorithm, rounds: int
    ) -> bytes:
        # hname = {"HMAC": "sha1"}.get(hash_algorithm.name, hash_algorithm.name) # TODO: Maybe important
        derived = pbkdf2(key, iv, self.key_length + self.iv_length, rounds, hash_algorithm.name)
        key, iv = derived[: self.key_length], derived[self.key_length :]
        key = key[: self.key_length]
        iv = iv[: self.iv_length]
        cipher = self.cipher_module.new(key, mode=self.cipher_module.MODE_CBC, IV=iv)
        return cipher.decrypt(data)

    def decrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = self.cipher_module.new(key, mode=self.cipher_module.MODE_CBC, IV=iv)
        return cipher.decrypt(data)


class __AES(CipherAlgorithm):
    id = 0x6611
    name = "AES"
    key_length = 128 // 8
    iv_length = 128 // 8
    block_length = 128 // 8
    cipher_module = AES


class __AES128(__AES):
    id = 0x660E
    name = "AES-128"


class __AES192(__AES):
    id = 0x660F
    name = "AES-192"
    key_length = 192 // 8


class __AES256(__AES):
    id = 0x6610
    name = "AES-256"
    key_length = 256 // 8


class __RC4(CipherAlgorithm):
    id = 0x6801
    name = "RC4"
    key_length = 40 // 8
    iv_length = 128 // 8
    block_length = 1 // 8
    cipher_module = ARC4


class HashAlgorithm(ABC):
    id: int
    name: str
    digest_length: int
    block_length: int

    def __init_subclass__(cls):
        HASH_ALGORITHMS[cls.id] = cls

    @classmethod
    def from_id(cls, id: int) -> HashAlgorithm:
        return HASH_ALGORITHMS[id]()

    def from_name(cls, name: str) -> Optional[HashAlgorithm]:
        res = [i for i in HASH_ALGORITHMS.values() if i.name == name]
        return res[0] if res else None

    @property
    @abstractproperty
    def id(self):
        raise NotImplementedError

    @property
    @abstractproperty
    def name(self):
        raise NotImplementedError

    @property
    @abstractproperty
    def digest_length(self):
        raise NotImplementedError

    @property
    @abstractproperty
    def block_length(self):
        raise NotImplementedError


class __MD5HashAlgorithm(HashAlgorithm):
    id = 0x8003
    name = "md5"
    digest_length = 128 // 8
    block_length = 512 // 8


class __SHA1HashAlgorithm(HashAlgorithm):
    id = 0x8004
    name = "sha1"
    digest_length = 160 // 8
    block_length = 512 // 8


class __HMACHashAlgorithm(__SHA1HashAlgorithm):
    """Synonymous to SHA1"""

    id = 0x8009


class __SHA256HashAlgorithm(HashAlgorithm):
    id = 0x8004
    name = "sha256"
    digest_length = 256 // 8
    block_length = 512 // 8


class __SHA384HashAlgorithm(HashAlgorithm):
    id = 0x800D
    name = "sha384"
    digest_length = 384 // 8
    block_length = 1024 // 8


class __SHA512HashAlgorithm(HashAlgorithm):
    id = 0x800E
    name = "sha512"
    digest_length = 512 // 8
    block_length = 1024 // 8


def pbkdf2(passphrase: bytes, salt: bytes, key_len: int, iterations: int, digest: Optional[str] = "sha1"):
    """Implementation of PBKDF2 that allows specifying digest algorithm.
    Returns the corresponding expanded key which is key_len long.
    """
    buff = b""
    i = 1
    while len(buff) < key_len:
        U = salt + struct.pack("!L", i)
        i += 1
        derived = hmac.new(passphrase, U, digestmod=digest).digest()
        for r in range(iterations - 1):
            actual = hmac.new(passphrase, derived, digestmod=digest).digest()
            derived = (
                "".join([chr(int(x, 16) ^ int(y, 16)) for (x, y) in zip(derived.hex(), actual.hex())]).encode().hex()
            )
            result = ""
            for j in range(len(derived)):
                if j % 2 == 1:
                    result += derived[j]
            derived = bytes.fromhex(result)
        buff += derived
    return buff[:key_len]


def dpapi_hmac(hash_algorithm: HashAlgorithm, pwd_hash: bytes, hmac_salt: bytes, value: bytes):
    """Internal function used to compute HMACs of DPAPI structures"""
    # hname = {"HMAC": "sha1"}.get(hash_algorithm.name, hash_algorithm.name) # TODO: Maybe importanbt?
    enc_key = hmac.new(pwd_hash, digestmod=hash_algorithm.name)
    enc_key.update(hmac_salt)
    enc_key = enc_key.digest()
    rv = hmac.new(enc_key, digestmod=hash_algorithm.name)
    rv.update(value)
    return rv.digest()


def crypt_session_key_type1(
    masterkey: bytes,
    nonce: Optional[bytes],
    hash_algo: HashAlgorithm,
    entropy: Optional[bytes] = None,
    strong_password: Optional[str] = None,
    smart_card_secret: Optional[bytes] = None,
    verif_blob: Optional[bytes] = None,
):
    """Computes the decryption key for Type1 DPAPI blob, given the masterkey and optional information.

    This implementation relies on a faulty implementation from Microsoft that does not respect the HMAC RFC.
    Instead of updating the inner pad, we update the outer pad...
    This algorithm is also used when checking the HMAC for integrity after decryption
    Args:
        masterkey: decrypted masterkey (should be 64 bytes long)
        nonce: this is the nonce contained in the blob or the HMAC in the blob (integrity check)
        hash_algo: a HashAlgorithm to use for calculating block sizes
        entropy: this is the optional entropy from CryptProtectData() API
        strong_password: optional password used for decryption or the blob itself
        smart_card_secret: optional MS Next Gen Crypto secret (e.g. from PIN code)
        verif_blob: optional encrypted blob used for integrity check
    Returns:
        decryption key
    """
    if len(masterkey) > 20:
        masterkey = hashlib.sha1(masterkey).digest()

    masterkey += b"\x00" * hash_algo.block_length
    pad1 = "".join(chr(masterkey[i] ^ 0x36) for i in range(hash_algo.block_length))
    pad2 = "".join(chr(masterkey[i] ^ 0x5C) for i in range(hash_algo.block_length))

    digest1 = hashlib.new(hash_algo.name)
    digest1.update(pad2.encode("latin1"))

    digest2 = hashlib.new(hash_algo.name)
    digest2.update(pad1.encode("latin1"))
    digest2.update(nonce)
    if smart_card_secret is not None:
        digest2.update(entropy + smart_card_secret)
        if verif_blob is not None:
            digest2.update(verif_blob)

    digest1.update(digest2.digest())
    if entropy is not None and smart_card_secret is None:
        digest1.update(entropy)
    if strong_password is not None:
        strong_password = hashlib.sha1(strong_password.rstrip("\x00").encode("UTF-16LE")).digest()
        digest1.update(strong_password)
    if smart_card_secret is None and verif_blob is not None:
        digest1.update(verif_blob)

    return digest1.digest()


def crypt_session_key_type2(
    masterkey: bytes,
    nonce: bytes,
    hash_algorithm: HashAlgorithm,
    entropy: Optional[bytes] = None,
    strong_password: Optional[str] = None,
    smart_card_secret: Optional[bytes] = None,
    verif_blob: Optional[bytes] = None,
):
    """Computes the decryption key for Type2 DPAPI blob, given the masterkey and optional information.

    This implementation relies on an RFC compliant HMAC implementation
    This algorithm is also used when checking the HMAC for integrity after decryption

    Args:
        masterkey: decrypted masterkey (should be 64 bytes long)
        nonce: this is the nonce contained in the blob or the HMAC in the blob (integrity check)
        hash_algo: a HashAlgorithm to use for calculating block sizes
        entropy: this is the optional entropy from CryptProtectData() API
        strong_password: optional password used for decryption or the blob itself
        smart_card_secret: optional MS Next Gen Crypto secret (e.g. from PIN code). Only for compatibility
        verif_blob: optional encrypted blob used for integrity check
    Returns:
        decryption key
    """
    if len(masterkey) > 20:
        masterkey = hashlib.sha1(masterkey).digest()

    digest = hmac.new(masterkey, digestmod=hash_algorithm.name)
    digest.update(nonce)
    if entropy is not None:
        digest.update(entropy)
    if strong_password is not None:
        strong_password = hashlib.sha512(strong_password.rstrip("\x00").encode("UTF-16LE")).digest()
        digest.update(strong_password)
    elif verif_blob is not None:
        digest.update(verif_blob)
    return digest.digest()


def derive_pwd_hash(pwdhash: bytes, userSID: str, digest="sha1"):
    """Internal use. Computes the encryption key from a user's password hash"""
    return hmac.new(pwdhash, (userSID + "\0").encode("UTF-16LE"), digestmod=digest).digest()
