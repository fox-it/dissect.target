from dissect.target.plugins.os.windows.dpapi.types.dpapi import DPAPIBlobStruct
from dissect.target.plugins.os.windows.dpapi import crypto


class DPAPIBlob:
    """Represents a DPAPI blob"""

    def __init__(self, data: bytes):
        self._blob = DPAPIBlobStruct.read(data)

        self.version = self._blob.dwVersion
        self.provider = self._blob.provider
        self.mkguid = self._blob.guid
        self.mkversion = self._blob.mkVersion
        self.flags = self._blob.flags
        self.description = self._blob.description.decode("UTF-16LE").encode("utf-8")
        self.cipherAlgo = crypto.CryptoAlgo(self._blob.CipherAlgId)
        self.keyLen = self._blob.keyLen
        self.hmac = self._blob.hmac
        self.strong = self._blob.strong
        self.hashAlgo = crypto.CryptoAlgo(self._blob.CryptAlgId)
        self.hashLen = self._blob.hashLen
        self.cipherText = self._blob.cipherText
        self.salt = self._blob.salt
        self.blob = self._blob.blob
        self.sign = self._blob.sign

        self.cleartext = None
        self.decrypted = False
        self.signComputed = None

    def decrypt(self, masterkey, entropy=None, strongPassword=None, smartCardSecret=None):
        """Try to decrypt the blob. Returns True/False
        :rtype : bool
        :param masterkey: decrypted masterkey value
        :param entropy: optional entropy for decrypting the blob
        :param strongPassword: optional password for decrypting the blob
        :param smartCardSecret: MS Next Gen Crypto secret (e.g. from PIN code)
        """
        for algo in [crypto.CryptSessionKeyType1, crypto.CryptSessionKeyType2]:
            sessionkey = algo(
                masterkey,
                self.salt,
                self.hashAlgo,
                entropy=entropy,
                smartcardsecret=smartCardSecret,
                strongPassword=strongPassword,
            )
            key = crypto.CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo)
            cipher = self.cipherAlgo.module.new(
                key[: int(self.cipherAlgo.keyLength)],
                mode=self.cipherAlgo.module.MODE_CBC,
                IV=b"\x00" * int(self.cipherAlgo.ivLength),
            )
            self.cleartext = cipher.decrypt(self.cipherText)
            padding = self.cleartext[-1]
            if padding <= self.cipherAlgo.blockSize:
                self.cleartext = self.cleartext[:-padding]
            # check against provided HMAC
            self.signComputed = algo(
                masterkey,
                self.hmac,
                self.hashAlgo,
                entropy=entropy,
                smartcardsecret=smartCardSecret,
                verifBlob=self.blob,
            )
            self.decrypted = self.signComputed == self.sign
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
                    "\tcipherAlgo   = %(cipherAlgo)r",
                    "\thashAlgo     = %(hashAlgo)r",
                )
            )
            % self.__dict__,
            "\tsalt         = %s" % self.salt.hex(),
            "\thmac         = %s" % self.hmac.hex(),
            "\tcipher       = %s" % self.cipherText.hex(),
            "\tsign         = %s" % self.sign.hex(),
        ]
        if self.signComputed is not None:
            s.append("\tsignComputed = %s" % self.signComputed.hex())
        if self.cleartext is not None:
            s.append("\tcleartext    = %r" % self.cleartext)
        return "\n".join(s)


# vim:ts=4:expandtab:sw=4
