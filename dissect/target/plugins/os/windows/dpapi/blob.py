from typing import Optional
from uuid import UUID

from dissect.cstruct import cstruct

from dissect.target.plugins.os.windows.dpapi.crypto import (
    CipherAlgorithm,
    HashAlgorithm,
    crypt_session_key_type1,
    crypt_session_key_type2,
)

blob_def = """
struct DPAPIBlob {
    DWORD   dwVersion;
    char    provider[16];
    DWORD   mkVersion;
    char    guid[16];
    DWORD   flags;
    DWORD   descriptionLength;
    char    description[descriptionLength];
    DWORD   CipherAlgId;
    DWORD   keyLen;
    DWORD   saltLength;
    char    salt[saltLength];
    DWORD   strongLength;
    char    strong[strongLength];
    DWORD   CryptAlgId;
    DWORD   hashLen;
    DWORD   hmacLength;
    char    hmac[hmacLength];
    DWORD   cipherTextLength;
    char    cipherText[cipherTextLength];
    DWORD   signLength;
    char    sign[signLength];
};
"""

c_blob = cstruct()
c_blob.load(blob_def)


class Blob:
    """Represents a DPAPI blob."""

    def __init__(self, data: bytes):
        self._blob = c_blob.DPAPIBlob(data)

        self.version = self._blob.dwVersion
        self.provider = str(UUID(bytes_le=self._blob.provider))
        self.mkversion = self._blob.mkVersion
        self.guid = str(UUID(bytes_le=self._blob.guid))
        self.flags = self._blob.flags
        self.description = self._blob.description.decode("utf-16-le")
        self.cipher_algorithm = CipherAlgorithm.from_id(self._blob.CipherAlgId)
        self.key_len = self._blob.keyLen
        self.salt = self._blob.salt
        self.strong = self._blob.strong
        self.hash_algorithm = HashAlgorithm.from_id(self._blob.CryptAlgId)
        self.hash_len = self._blob.hashLen
        self.hmac = self._blob.hmac
        self.cipher_text = self._blob.cipherText

        # All the blob data between the version, provider and sign fields
        # TODO: Replace with future offsetof function in cstruct
        self.blob = data[c_blob.DPAPIBlob.lookup["mkVersion"].offset : -(self._blob.signLength + len(c_blob.DWORD))]
        self.sign = self._blob.sign

        self.clear_text = None
        self.decrypted = False
        self.sign_computed = None

    def decrypt(
        self,
        master_key: bytes,
        entropy: Optional[bytes] = None,
        strong_password: Optional[str] = None,
        smart_card_secret: Optional[bytes] = None,
    ) -> bool:
        """Try to decrypt the blob with the given master key.

        Args:
            master_key: Decrypted master key value.
            entropy: Optional entropy for decrypting the blob.
            strong_password: Optional password for decrypting the blob.
            smart_card_secret: MS Next Gen Crypto secret (e.g. from PIN code).

        Returns:
            True if decryption is succesful, False otherwise.
        """
        if self.decrypted:
            return True

        for algo in [crypt_session_key_type1, crypt_session_key_type2]:
            session_key = algo(
                master_key,
                self.salt,
                self.hash_algorithm,
                entropy=entropy,
                smart_card_secret=smart_card_secret,
                strong_password=strong_password,
            )
            key = self.cipher_algorithm.derive_key(session_key, self.hash_algorithm)
            self.clear_text = self.cipher_algorithm.decrypt(self.cipher_text, key)

            padding = self.clear_text[-1]
            if padding <= self.cipher_algorithm.block_length:
                self.clear_text = self.clear_text[:-padding]

            # Check against provided HMAC
            self.sign_computed = algo(
                master_key,
                self.hmac,
                self.hash_algorithm,
                entropy=entropy,
                smart_card_secret=smart_card_secret,
                verify_blob=self.blob,
            )

            self.decrypted = self.sign_computed == self.sign
            if self.decrypted:
                return True

        self.decrypted = False
        return self.decrypted

    def __repr__(self) -> str:
        s = [
            "DPAPI BLOB",
            "\n".join(
                (
                    "\tversion      = %(version)d",
                    "\tprovider     = %(provider)s",
                    "\tmkey         = %(guid)s",
                    "\tflags        = %(flags)#x",
                    "\tdescr        = %(description)s",
                    "\tcipher_algo   = %(cipher_algorithm)r",
                    "\thash_algo     = %(hash_algorithm)r",
                )
            )
            % self.__dict__,
            "\tsalt         = %s" % self.salt.hex(),
            "\thmac         = %s" % self.hmac.hex(),
            "\tcipher       = %s" % self.cipher_text.hex(),
            "\tsign         = %s" % self.sign.hex(),
        ]
        if self.sign_computed is not None:
            s.append("\tsign_computed = %s" % self.sign_computed.hex())
        if self.clear_text is not None:
            s.append("\tcleartext    = %r" % self.clear_text)
        return "\n".join(s)
