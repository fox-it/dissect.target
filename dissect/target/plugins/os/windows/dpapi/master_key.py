import hashlib
from io import BytesIO
from typing import BinaryIO

from dissect.cstruct import cstruct

from dissect.target.plugins.os.windows.dpapi.crypto import (
    CipherAlgorithm,
    HashAlgorithm,
    derive_password_hash,
    dpapi_hmac,
)

master_key_def = """
struct DomainKey {
    DWORD   dwVersion;
    DWORD   secretLen;
    DWORD   accessCheckLen;
    char    guid[16];
    char    encryptedSecret[secretLen];
    char    accessCheckLen[accessCheckLen];
};

struct CredHist {
    DWORD   dwVersion;
    char    guid[16];
};

struct MasterKey {
    DWORD   dwVersion;
    char    pSalt[16];
    DWORD   dwPBKDF2IterationCount;
    DWORD   HMACAlgId;                  // This is actually ALG_ID
    DWORD   CryptAlgId;                 // This is actually ALG_ID
    // BYTE    pKey[];
};

struct CredSystem {
    DWORD   dwRevision;
    char    pMachine[20];
    char    pUser[20];
};

struct MasterKeyFileHeader {
    DWORD   dwVersion;                  // Masterkey version. Should be 1 or 2
    DWORD   dwReserved1;
    DWORD   dwReserved2;
    WCHAR   szGuid[36];                 // GUID of master key. Should match filename
    DWORD   dwUnused1;
    DWORD   dwUnused2;
    DWORD   dwPolicy;
    QWORD   qwUserKeySize;
    QWORD   qwLocalEncKeySize;
    QWORD   qwLocalKeySize;
    QWORD   qwDomainKeySize;
};
"""
c_master_key = cstruct()
c_master_key.load(master_key_def)


class MasterKey:
    def __init__(self, data: bytes) -> None:
        buf = BytesIO(data)
        self._mk = c_master_key.MasterKey(buf)
        self._mk_key = buf.read()

        self.key = None
        self.key_hash = None
        self.decrypted = False

    def decrypt_with_hash(self, user_sid: str, password_hash: bytes) -> bool:
        """Decrypts the master key with the given user's SID and password hash."""
        return self.decrypt_with_key(derive_password_hash(password_hash, user_sid))

    def decrypt_with_hash_10(self, user_sid: str, password_hash: bytes) -> bool:
        """Decrypts the master key with the given user's hash and SID.

        Newer version of :meth:`~MasterKey.decrypt_with_hash`
        """
        user_sid_encoded = user_sid.encode("utf-16-le")
        pwd_hash1 = hashlib.pbkdf2_hmac("sha256", password_hash, user_sid_encoded, 10000)
        pwd_hash2 = hashlib.pbkdf2_hmac("sha256", pwd_hash1, user_sid_encoded, 1)[0:16]
        return self.decrypt_with_key(derive_password_hash(pwd_hash2, user_sid))

    def decrypt_with_password(self, user_sid: str, pwd: str) -> bool:
        """Decrypts the master key with the given user's password and SID."""
        for algo in ["sha1", "md4"]:
            pwd_hash = hashlib.new(algo, pwd.encode("utf-16-le")).digest()
            self.decrypt_with_key(derive_password_hash(pwd_hash, user_sid))
            if self.decrypted:
                break

        return self.decrypted

    def decrypt_with_key(self, key: bytes) -> bool:
        """Decrypts the master key with the given encryption key.

        This function also extracts the HMAC part of the decrypted data and compares it with the computed one.

        Note that once successfully decrypted, this function turns into a no-op.
        """
        if self.decrypted:
            return True

        if not self._mk_key:
            return False

        # Compute encryption key
        hash_algo = HashAlgorithm.from_id(self._mk.HMACAlgId)
        cipher_algo = CipherAlgorithm.from_id(self._mk.CryptAlgId)

        data = cipher_algo.decrypt_with_hmac(
            self._mk_key,
            key,
            self._mk.pSalt,
            hash_algo,
            self._mk.dwPBKDF2IterationCount,
        )

        self.key = data[-64:]
        self.hmac_salt = data[:16]
        self.hmac = data[16 : 16 + int(hash_algo.digest_length)]
        self.hmac_computed = dpapi_hmac(key, self.hmac_salt, self.key, hash_algo)
        self.decrypted = self.hmac == self.hmac_computed
        if self.decrypted:
            self.key_hash = hashlib.sha1(self.key).digest()

        return self.decrypted


class MasterKeyFile:
    def __init__(self, fh: BinaryIO):
        self._mk_header = c_master_key.MasterKeyFileHeader(fh)
        self._user_mk = None

        # User Master Key
        if self._mk_header.qwUserKeySize:
            self._user_mk = MasterKey(fh.read(self._mk_header.qwUserKeySize))

        # Here we would also parse the rest of the keys, but as of now we don't decrypt them
        self._backup_mk = None
        self._credhist_mk = None
        self._domain_mk = None

    @property
    def decrypted(self) -> bool:
        return self._user_mk.decrypted

    @property
    def key(self) -> bytes:
        return self._user_mk.key

    def decrypt_with_hash(self, user_sid: str, password_hash: bytes) -> bool:
        """See :meth:`MasterKey.decrypt_with_hash` and :meth:`MasterKey.decrypt_with_hash_10`."""
        if not self._user_mk.decrypted:
            self._user_mk.decrypt_with_hash_10(user_sid, password_hash)

        if not self._user_mk.decrypted:
            self._user_mk.decrypt_with_hash(user_sid, password_hash)

        return self._user_mk.decrypted

    def decrypt_with_password(self, user_sid: str, pwd: str) -> bool:
        """See :meth:`MasterKey.decrypt_with_password`."""
        return self._user_mk.decrypt_with_password(user_sid, pwd)

    def decrypt_with_key(self, key: bytes) -> bool:
        """See :meth:`MasterKey.decrypt_with_key`."""
        return self._user_mk.decrypt_with_key(key)


class CredSystem:
    def __init__(self, buf: bytes):
        self._struct = c_master_key.CredSystem(buf)
        self.machine_key = self._struct.pMachine
        self.user_key = self._struct.pUser
