import hmac
import array
import struct
import hashlib
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Cipher import DES
from Crypto.Cipher import DES3


class CryptoAlgo(object):
    """This class is used to wrap Microsoft algorithm IDs with M2Crypto"""

    class Algo(object):
        def __init__(self, data):
            self.data = data

        def __getattr__(self, attr):
            if attr in self.data:
                return self.data[attr]
            raise AttributeError(attr)

    _crypto_data = {}

    @classmethod
    def add_algo(cls, algnum, **kargs):
        cls._crypto_data[algnum] = cls.Algo(kargs)
        if "name" in kargs:
            kargs["ID"] = algnum
            cls._crypto_data[kargs["name"]] = cls.Algo(kargs)

    @classmethod
    def get_algo(cls, algnum):
        return cls._crypto_data[algnum]

    def __init__(self, i):
        self.algnum = i
        self.algo = CryptoAlgo.get_algo(i)

    name = property(lambda self: self.algo.name)
    module = property(lambda self: self.algo.module)
    keyLength = property(lambda self: self.algo.keyLength / 8)
    ivLength = property(lambda self: self.algo.IVLength / 8)
    blockSize = property(lambda self: self.algo.blockLength / 8)
    digestLength = property(lambda self: self.algo.digestLength / 8)

    def do_fixup_key(self, key):
        try:
            return self.algo.keyFixup.__call__(key)
        except AttributeError:
            return key

    def __repr__(self):
        return "%s [%#x]" % (self.algo.name, self.algnum)


def des_set_odd_parity(key):
    # fmt: off
    _lut = [1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14, 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31, 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47, 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62, 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79, 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94, 97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110, 112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158, 161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174, 176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191, 193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206, 208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223, 224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254] # noqa
    # fmt: on
    tmp = array.array("B")
    tmp.fromstring(key)
    for i, v in enumerate(tmp):
        tmp[i] = _lut[v]
    return tmp.tostring()


CryptoAlgo.add_algo(
    0x6603,
    name="DES3",
    keyLength=192,
    IVLength=64,
    blockLength=64,
    module=DES3,
    keyFixup=des_set_odd_parity,
)
CryptoAlgo.add_algo(0x6611, name="AES", keyLength=128, IVLength=128, blockLength=128, module=AES)
CryptoAlgo.add_algo(0x660E, name="AES-128", keyLength=128, IVLength=128, blockLength=128, module=AES)
CryptoAlgo.add_algo(0x660F, name="AES-192", keyLength=192, IVLength=128, blockLength=128, module=AES)
CryptoAlgo.add_algo(0x6610, name="AES-256", keyLength=256, IVLength=128, blockLength=128, module=AES)
CryptoAlgo.add_algo(
    0x6601,
    name="DES",
    keyLength=64,
    IVLength=64,
    blockLength=64,
    module=DES,
    keyFixup=des_set_odd_parity,
)
CryptoAlgo.add_algo(0x6801, name="RC4", keyLength=40, IVLength=128, blockLength=1, module=ARC4)

CryptoAlgo.add_algo(0x8009, name="HMAC", digestLength=160, blockLength=512)

CryptoAlgo.add_algo(0x8003, name="md5", digestLength=128, blockLength=512)

CryptoAlgo.add_algo(0x8004, name="sha1", digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x800C, name="sha256", digestLength=256, blockLength=512)
CryptoAlgo.add_algo(0x800D, name="sha384", digestLength=384, blockLength=1024)
CryptoAlgo.add_algo(0x800E, name="sha512", digestLength=512, blockLength=1024)


def getDigestmod(digest):
    Dmod = {
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    return Dmod.get(digest, hashlib.sha1)


def derivePwdHash(pwdhash, userSID, digest="sha1"):
    """Internal use. Computes the encryption key from a user's password hash"""
    # return hmac.new(pwdhash, (userSID + "\0").encode("UTF-16LE"), digestmod=lambda: hashlib.new(digest)).digest()
    return hmac.new(pwdhash, (userSID + "\0").encode("UTF-16LE"), digestmod=getDigestmod(digest)).digest()


def dataDecrypt(cipherAlgo, hashAlgo, raw, encKey, iv, rounds):
    """Internal use. Decrypts data stored in DPAPI structures."""
    hname = {"HMAC": "sha1"}.get(hashAlgo.name, hashAlgo.name)
    derived = pbkdf2(encKey, iv, int(cipherAlgo.keyLength + cipherAlgo.ivLength), rounds, hname)
    key, iv = derived[: int(cipherAlgo.keyLength)], derived[int(cipherAlgo.keyLength) :]
    key = key[: int(cipherAlgo.keyLength)]
    iv = iv[: int(cipherAlgo.ivLength)]
    cipher = cipherAlgo.module.new(key, mode=cipherAlgo.module.MODE_CBC, IV=iv)
    cleartxt = cipher.decrypt(raw)
    return cleartxt


def pbkdf2(passphrase, salt, keylen, iterations, digest="sha1"):
    """Implementation of PBKDF2 that allows specifying digest algorithm.
    Returns the corresponding expanded key which is keylen long.
    """
    buff = b""
    i = 1
    while len(buff) < keylen:
        U = salt + struct.pack("!L", i)
        i += 1
        derived = hmac.new(passphrase, U, digestmod=getDigestmod(digest)).digest()
        for r in range(iterations - 1):
            actual = hmac.new(passphrase, derived, digestmod=getDigestmod(digest)).digest()
            derived = (
                "".join([chr(int(x, 16) ^ int(y, 16)) for (x, y) in zip(derived.hex(), actual.hex())]).encode().hex()
            )
            result = ""
            for j in range(len(derived)):
                if j % 2 == 1:
                    result += derived[j]
            derived = bytes.fromhex(result)
        buff += derived
    return buff[:keylen]


def DPAPIHmac(hashAlgo, pwdhash, hmacSalt, value):
    """Internal function used to compute HMACs of DPAPI structures"""
    hname = {"HMAC": "sha1"}.get(hashAlgo.name, hashAlgo.name)
    # encKey = hmac.new(pwdhash, digestmod=lambda: hashlib.new(hname))
    encKey = hmac.new(pwdhash, digestmod=getDigestmod(hname))
    encKey.update(hmacSalt)
    encKey = encKey.digest()
    # rv = hmac.new(encKey, digestmod=lambda: hashlib.new(hname))
    rv = hmac.new(encKey, digestmod=getDigestmod(hname))
    rv.update(value)
    return rv.digest()


def CryptSessionKeyType1(
    masterkey, nonce, hashAlgo, entropy=None, strongPassword=None, smartcardsecret=None, verifBlob=None
):
    """Computes the decryption key for Type1 DPAPI blob, given the masterkey and optional information.

    This implementation relies on a faulty implementation from Microsoft that does not respect the HMAC RFC.
    Instead of updating the inner pad, we update the outer pad...
    This algorithm is also used when checking the HMAC for integrity after decryption

    :param masterkey: decrypted masterkey (should be 64 bytes long)
    :param nonce: this is the nonce contained in the blob or the HMAC in the blob (integrity check)
    :param entropy: this is the optional entropy from CryptProtectData() API
    :param strongPassword: optional password used for decryption or the blob itself
    :param smartcardsecret: optional MS Next Gen Crypto secret (e.g. from PIN code)
    :param verifBlob: optional encrypted blob used for integrity check
    :returns: decryption key
    :rtype : str
    """
    if len(masterkey) > 20:
        masterkey = hashlib.sha1(masterkey).digest()

    masterkey += ("\x00" * int(hashAlgo.blockSize)).encode()
    pad1 = "".join(chr(masterkey[i] ^ 0x36) for i in range(int(hashAlgo.blockSize)))
    pad2 = "".join(chr(masterkey[i] ^ 0x5C) for i in range(int(hashAlgo.blockSize)))

    digest1 = hashlib.new(hashAlgo.name)
    digest1.update(pad2.encode("latin1"))

    digest2 = hashlib.new(hashAlgo.name)
    digest2.update(pad1.encode("latin1"))
    digest2.update(nonce)
    if smartcardsecret is not None:
        digest2.update(entropy + smartcardsecret)
        if verifBlob is not None:
            digest2.update(verifBlob)

    digest1.update(digest2.digest())
    if entropy is not None and smartcardsecret is None:
        digest1.update(entropy)
    if strongPassword is not None:
        strongPassword = hashlib.sha1(strongPassword.rstrip("\x00").encode("UTF-16LE")).digest()
        digest1.update(strongPassword)
    if smartcardsecret is None and verifBlob is not None:
        digest1.update(verifBlob)

    return digest1.digest()


def CryptSessionKeyType2(
    masterkey, nonce, hashAlgo, entropy=None, strongPassword=None, smartcardsecret=None, verifBlob=None
):
    """Computes the decryption key for Type2 DPAPI blob, given the masterkey and optional information.

    This implementation relies on an RFC compliant HMAC implementation
    This algorithm is also used when checking the HMAC for integrity after decryption

    :param masterkey: decrypted masterkey (should be 64 bytes long)
    :param nonce: this is the nonce contained in the blob or the HMAC in the blob (integrity check)
    :param entropy: this is the optional entropy from CryptProtectData() API
    :param strongPassword: optional password used for decryption or the blob itself
    :param smartcardsecret: optional MS Next Gen Crypto secret (e.g. from PIN code)
    :param verifBlob: optional encrypted blob used for integrity check
    :returns: decryption key
    :rtype : str
    """
    if len(masterkey) > 20:
        masterkey = hashlib.sha1(masterkey).digest()

    digest = hmac.new(masterkey, digestmod=getDigestmod(hashAlgo.name))
    digest.update(nonce)
    if entropy is not None:
        digest.update(entropy)
    if strongPassword is not None:
        strongPassword = hashlib.sha512(strongPassword.rstrip("\x00").encode("UTF-16LE")).digest()
        digest.update(strongPassword)
    elif verifBlob is not None:
        digest.update(verifBlob)
    return digest.digest()


def CryptDeriveKey(h, cipherAlgo, hashAlgo):
    """Internal use. Mimics the corresponding native Microsoft function"""
    if len(h) > hashAlgo.blockSize:
        h = hashlib.new(hashAlgo.name, h).digest()
    if len(h) >= cipherAlgo.keyLength:
        return h
    h += ("\x00" * int(hashAlgo.blockSize)).encode()
    pad1 = "".join(chr(h[i] ^ 0x36) for i in range(int(hashAlgo.blockSize)))
    pad2 = "".join(chr(h[i] ^ 0x5C) for i in range(int(hashAlgo.blockSize)))
    k = (
        hashlib.new(hashAlgo.name, pad1.encode("latin1")).digest()
        + hashlib.new(hashAlgo.name, pad2.encode("latin1")).digest()
    )
    k = cipherAlgo.do_fixup_key(k)
    return k
