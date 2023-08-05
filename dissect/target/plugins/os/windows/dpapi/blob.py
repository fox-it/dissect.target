from typing import Optional

from dissect.target.plugins.os.windows.dpapi import crypto
from dissect.target.plugins.os.windows.dpapi.types.dpapi import DPAPIBlobStruct


class Blob:
    """Represents a DPAPI blob"""

    def __init__(self, data: bytes):
        self._blob = DPAPIBlobStruct.read(data)

        self.version = self._blob.dwVersion
        self.provider = self._blob.provider
        self.mkguid = self._blob.guid
        self.mkversion = self._blob.mkVersion
        self.flags = self._blob.flags
        self.description = self._blob.description.decode("utf-16-le").encode("utf-8")
        self.cipher_algo = crypto.CipherAlgorithm.from_id(self._blob.CipherAlgId)
        self.key_len = self._blob.keyLen
        self.hmac = self._blob.hmac
        self.strong = self._blob.strong
        self.hash_algo = crypto.HashAlgorithm.from_id(self._blob.CryptAlgId)
        self.hash_len = self._blob.hashLen
        self.ciphertext = self._blob.cipherText
        self.salt = self._blob.salt

        self.blob = self._blob.blob
        self.sign = self._blob.sign

        self.cleartext = None
        self.decrypted = False
        self.sign_computed = None

    def decrypt(
        self,
        masterkey: bytes,
        entropy: Optional[bytes] = None,
        strong_password: Optional[str] = None,
        smart_card_secret: Optional[bytes] = None,
    ):
        """Try to decrypt the blob with the given masterkey
        Args:
            masterkey: decrypted masterkey value
            entropy: optional entropy for decrypting the blob
            strong_password: optional password for decrypting the blob
            smart_card_secret: MS Next Gen Crypto secret (e.g. from PIN code)
        Returns:
            True if decryption is succesful, False otherwise
        """
        for algo in [crypto.crypt_session_key_type1, crypto.crypt_session_key_type2]:
            sessionkey = algo(
                masterkey,
                self.salt,
                self.hash_algo,
                entropy=entropy,
                smart_card_secret=smart_card_secret,
                strong_password=strong_password,
            )
            key = self.cipher_algo.derive_key(sessionkey, self.hash_algo)
            self.cleartext = self.cipher_algo.decrypt(
                self.ciphertext, key[: self.cipher_algo.key_length], b"\x00" * self.cipher_algo.iv_length
            )
            padding = self.cleartext[-1]
            if padding <= self.cipher_algo.block_length:
                self.cleartext = self.cleartext[:-padding]
            # check against provided HMAC
            self.sign_computed = algo(
                masterkey,
                self.hmac,
                self.hash_algo,
                entropy=entropy,
                smart_card_secret=smart_card_secret,
                verif_blob=self.blob,
            )
            self.decrypted = self.sign_computed == self.sign
            if self.decrypted:
                return True
        self.decrypted = False
        return self.decrypted

    def __repr__(self):
        s = [
            "DPAPI BLOB",
            "\n".join(
                (
                    "\tversion      = %(version)d",
                    "\tprovider     = %(provider)s",
                    "\tmkey         = %(mkguid)s",
                    "\tflags        = %(flags)#x",
                    "\tdescr        = %(description)s",
                    "\tcipher_algo   = %(cipher_algo)r",
                    "\thash_algo     = %(hash_algo)r",
                )
            )
            % self.__dict__,
            "\tsalt         = %s" % self.salt.hex(),
            "\thmac         = %s" % self.hmac.hex(),
            "\tcipher       = %s" % self.ciphertext.hex(),
            "\tsign         = %s" % self.sign.hex(),
        ]
        if self.sign_computed is not None:
            s.append("\tsign_computed = %s" % self.sign_computed.hex())
        if self.cleartext is not None:
            s.append("\tcleartext    = %r" % self.cleartext)
        return "\n".join(s)
