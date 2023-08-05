import hashlib
from io import BytesIO
from typing import BinaryIO, Optional

from dissect.target.plugins.os.windows.dpapi.crypto import (
    CipherAlgorithm,
    HashAlgorithm,
    derive_pwd_hash,
    dpapi_hmac,
)
from dissect.target.plugins.os.windows.dpapi.types.masterkey import CredHist, DomainKey
from dissect.target.plugins.os.windows.dpapi.types.masterkey import (
    MasterKey as _c_MasterKey,
)
from dissect.target.plugins.os.windows.dpapi.types.masterkey import MasterKeyFileHeader


class MasterKey:
    def __init__(self, data: bytes) -> None:
        self.decrypted = False
        self.mk = _c_MasterKey.read(data)
        self.key = None
        self.key_hash = None

    def decrypt_with_hash(self, user_SID: str, pwd_hash: bytes) -> None:
        """Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decryptWithKey()
        """
        self.decrypt_with_key(derive_pwd_hash(pwd_hash, user_SID))

    def decrypt_with_hash_10(self, user_SID: str, pwd_hash: bytes) -> None:
        """Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decryptWithKey().
        Newer version of `decryptWithHash`
        """
        pwd_hash1 = hashlib.pbkdf2_hmac("sha256", pwd_hash, user_SID.encode("UTF-16LE"), 10000)
        pwd_hash2 = hashlib.pbkdf2_hmac("sha256", pwd_hash1, user_SID.encode("UTF-16LE"), 1)[0:16]
        self.decrypt_with_key(derive_pwd_hash(pwd_hash2, user_SID))

    def decrypt_with_password(self, user_SID: str, pwd: str) -> None:
        """Decrypts the masterkey with the given user's password and SID.
        Simply computes the corresponding key, then calls self.decryptWithKey()
        """
        for algo in ["sha1", "md4"]:
            self.decrypt_with_key(derive_pwd_hash(hashlib.new(algo, pwd.encode("UTF-16LE")).digest(), user_SID))
            if self.decrypted:
                break

    def decrypt_with_key(self, pwd_hash: bytes) -> None:
        """Decrypts the masterkey with the given encryption key. This function
        also extracts the HMAC part of the decrypted stuff and compare it with
        the computed one.

        Note that, once successfully decrypted, the masterkey will not be
        decrypted anymore; this function will simply return.
        """
        if self.decrypted:
            return
        if not self.mk.pKey:
            return
        # Compute encryption key
        hash_algo = HashAlgorithm.from_id(self.mk.HMACAlgId)
        cleartxt = CipherAlgorithm.from_id(self.mk.CryptAlgId).decrypt_with_hmac(
            bytes(self.mk.pKey),
            bytes(pwd_hash),
            bytes(self.mk.pSalt),
            hash_algo,
            self.mk.dwPBKDF2IterationCount,
        )
        self.key = cleartxt[-64:]
        self.hmac_salt = cleartxt[:16]
        self.hmac = cleartxt[16 : 16 + int(hash_algo.digest_length)]
        self.hmac_computed = dpapi_hmac(hash_algo, bytes(pwd_hash), self.hmac_salt, self.key)
        self.decrypted = self.hmac == self.hmac_computed
        if self.decrypted:
            self.key_hash = hashlib.sha1(self.key).digest()


class MasterKeyFile:
    def __init__(self):
        self.decrypted: bool = False
        self._mk_header: Optional[MasterKeyFileHeader] = None
        self._user_mk: Optional[MasterKey] = None
        self._backup_mk: Optional[MasterKey] = None
        self._credhist_mk: Optional[CredHist] = None
        self._domain_mk: Optional[DomainKey] = None

    def read(self, obj: BinaryIO) -> None:
        if isinstance(obj, (bytes, memoryview, bytearray)):
            obj = BytesIO(obj)
        return self._read(obj)

    def _read(self, stream: BytesIO) -> None:
        self._mk_header = MasterKeyFileHeader.read(stream)
        # User Master Key
        if self._mk_header.qwUserKeySize:
            self._user_mk = MasterKey(stream.read(self._mk_header.qwUserKeySize))

        # Here we would also parse the rest of the keys, but as of now we don't decrypt them.

    def decrypt_with_hash(self, user_SID: str, h: bytes) -> None:
        """See MasterKey.decryptWithHash()"""
        if not self._user_mk.decrypted:
            self._user_mk.decrypt_with_hash_10(user_SID, h)
            if not self._user_mk.decrypted:
                self._user_mk.decrypt_with_hash(user_SID, h)
        self.decrypted = self._user_mk.decrypted

    def decrypt_with_password(self, user_SID: str, pwd: str) -> None:
        """See MasterKey.decryptWithPassword()"""
        for algo in ["sha1", "md4"]:
            self.decrypt_with_hash(user_SID, hashlib.new(algo, pwd.encode("UTF-16LE")).digest())
            if self.decrypted:
                break

    def decrypt_with_key(self, pwd_hash: bytes) -> None:
        """See MasterKey.decryptWithKey()"""
        if not self._user_mk.decrypted:
            self._user_mk.decrypt_with_key(pwd_hash)
        self.decrypted = self._user_mk.decrypted

    @property
    def key(self) -> bytes:
        return self._user_mk.key
