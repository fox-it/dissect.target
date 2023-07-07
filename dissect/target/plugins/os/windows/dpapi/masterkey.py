import hashlib

from io import BytesIO
from typing import BinaryIO, Optional

from dissect.target.plugins.os.windows.dpapi.types.masterkey import (
    CredHist,
    DomainKey,
    MasterKey as _c_MasterKey,
    MasterKeyFileHeader,
)
from dissect.target.plugins.os.windows.dpapi.crypto import (
    CryptoAlgo,
    DPAPIHmac,
    dataDecrypt,
    derivePwdHash,
)


class MasterKey:
    def __init__(self, data: bytes) -> None:
        self.decrypted = False
        self.mk = _c_MasterKey.read(data)
        self.key = None
        self.key_hash = None

    def decryptWithHash(self, userSID, pwdhash):
        """Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decryptWithKey()
        """
        self.decryptWithKey(derivePwdHash(pwdhash, userSID))

    def decryptWithHash10(self, userSID, pwdhash):
        """Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decryptWithKey()
        """
        pwdhash1 = hashlib.pbkdf2_hmac("sha256", pwdhash, userSID.encode("UTF-16LE"), 10000)
        pwdhash2 = hashlib.pbkdf2_hmac("sha256", pwdhash1, userSID.encode("UTF-16LE"), 1)[0:16]
        self.decryptWithKey(derivePwdHash(pwdhash2, userSID))

    def decryptWithPassword(self, userSID, pwd):
        """Decrypts the masterkey with the given user's password and SID.
        Simply computes the corresponding key, then calls self.decryptWithKey()

        """
        for algo in ["sha1", "md4"]:
            self.decryptWithKey(derivePwdHash(hashlib.new(algo, pwd.encode("UTF-16LE")).digest(), userSID))
            if self.decrypted:
                break

    def decryptWithKey(self, pwdhash):
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
        hashAlgo = CryptoAlgo(self.mk.HMACAlgId)
        cleartxt = dataDecrypt(
            CryptoAlgo(self.mk.CryptAlgId),
            hashAlgo,
            bytes(self.mk.pKey),
            bytes(pwdhash),
            bytes(self.mk.pSalt),
            self.mk.dwPBKDF2IterationCount,
        )
        self.key = cleartxt[-64:]
        self.hmacSalt = cleartxt[:16]
        self.hmac = cleartxt[16 : 16 + int(hashAlgo.digestLength)]
        self.hmacComputed = DPAPIHmac(hashAlgo, bytes(pwdhash), self.hmacSalt, self.key)
        self.decrypted = self.hmac == self.hmacComputed
        if self.decrypted:
            self.key_hash = hashlib.sha1(self.key).digest()


class MasterKeyFile:
    def __init__(self) -> None:
        self.decrypted: bool = False
        self._mk_header: Optional[MasterKeyFileHeader] = None
        self._user_mk: Optional[MasterKey] = None
        self._backup_mk: Optional[MasterKey] = None
        self._credhist_mk: Optional[CredHist] = None
        self._domain_mk: Optional[DomainKey] = None

    def read(self, obj: BinaryIO):
        if isinstance(obj, (bytes, memoryview, bytearray)):
            obj = BytesIO(obj)
        return self._read(obj)

    def _read(self, stream: BytesIO):
        self._mk_header = MasterKeyFileHeader.read(stream)
        # User Master Key
        if self._mk_header.qwUserKeySize:
            self._user_mk = MasterKey(stream.read(self._mk_header.qwUserKeySize))

        # Here we can also parse the rest of the keys, as of now we don't decrypt them

    def decryptWithHash(self, userSID, h):
        """See MasterKey.decryptWithHash()"""
        if not self._user_mk.decrypted:
            self._user_mk.decryptWithHash10(userSID, h)
            if not self._user_mk.decrypted:
                self._user_mk.decryptWithHash(userSID, h)
        self.decrypted = self._user_mk.decrypted

    def decryptWithPassword(self, userSID, pwd):
        """See MasterKey.decryptWithPassword()"""
        for algo in ["sha1", "md4"]:
            self.decryptWithHash(userSID, hashlib.new(algo, pwd.encode("UTF-16LE")).digest())

            if self.decrypted:
                break

    def decryptWithKey(self, pwdhash):
        """See MasterKey.decryptWithKey()"""
        if not self._user_mk.decrypted:
            self._user_mk.decryptWithKey(pwdhash)
        self.decrypted = self._user_mk.decrypted

    def get_key(self):
        return self._user_mk.key
