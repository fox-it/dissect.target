import hashlib
from functools import cached_property
from struct import unpack

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import InternalPlugin

try:
    from Crypto.Cipher import AES, ARC4, DES

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class LSAPlugin(InternalPlugin):
    """Windows LSA Plugin.

    Resources:
        - https://moyix.blogspot.com/2008/02/decrypting-lsa-secrets.html (Windows XP)
        - https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py
    """
    __namespace__ = "lsa"

    SECURITY_POLICY_KEY = "HKEY_LOCAL_MACHINE\\SECURITY\\Policy"
    SYSTEM_KEY = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA"

    def check_compatible(self) -> None:
        if not HAS_CRYPTO:
            raise UnsupportedPluginError("Missing pycryptodome dependency")

        if not self.target.has_function("registry") or not list(self.target.registry.keys(self.SYSTEM_KEY)):
            raise UnsupportedPluginError("Registry key not found: %s", self.SYSTEM_KEY)

    @cached_property
    def syskey(self) -> bytes:
        """Return byte value of Windows system SYSKEY, also called BootKey."""
        lsa = self.target.registry.key(self.SYSTEM_KEY)
        syskey_keys = ["JD", "Skew1", "GBG", "Data"]
        # This magic value rotates the order of the data
        alterator = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]

        r = bytes.fromhex("".join([lsa.subkey(key).class_name for key in syskey_keys]))
        return bytes(r[i] for i in alterator)

    @cached_property
    def lsakey(self) -> bytes:
        """Decrypt and return the LSA key of the Windows system."""
        security_pol = self.target.registry.key(self.SECURITY_POLICY_KEY)

        # Windows Vista and newer
        if key := security_pol.subkeys().mapping.get("PolEKList"):
            enc_key = key.value("(Default)").value
            lsa_key = _decrypt_aes(enc_key, self.syskey)
            return lsa_key[68:100]

        # Windows XP
        if key := security_pol.subkeys().mapping.get("PolSecretEncryptionKey"):
            enc_key = key.value("(Default)").value
            lsa_key = _decrypt_rc4(enc_key, self.syskey)
            return lsa_key[16:32]

        raise ValueError("Unable to determine LSA policy key location in registry")

    @cached_property
    def secrets(self) -> dict[str, bytes]:
        """Return dict of Windows system decrypted LSA secrets."""
        result = {}

        reg_secrets = self.target.registry.key(self.SECURITY_POLICY_KEY).subkey("Secrets")
        for subkey in reg_secrets.subkeys():
            enc_data = subkey.subkey("CurrVal").value("(Default)").value

            # Windows Vista or newer
            if float(self.target._os._nt_version()) >= 6.0:
                secret = _decrypt_aes(enc_data, self.lsakey)

            # Windows XP
            else:
                secret = _decrypt_des(enc_data, self.lsakey)

            result[subkey.name] = secret

        return result


def _decrypt_aes(data: bytes, key: bytes) -> bytes:
    ctx = hashlib.sha256()
    ctx.update(key)

    tmp = data[28:60]
    for _ in range(1, 1000 + 1):
        ctx.update(tmp)

    aeskey = ctx.digest()
    iv = b"\x00" * 16

    result = []

    # TODO: use Crypto.Util.Padding.pad
    for i in range(60, len(data), 16):
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        result.append(cipher.decrypt(data[i : i + 16].ljust(16, b"\x00")))

    return b"".join(result)


def _decrypt_rc4(data: bytes, key: bytes) -> bytes:
    md5 = hashlib.md5()
    md5.update(key)
    for _ in range(1000):
        md5.update(data[60:76])
    rc4_key = md5.digest()

    cipher = ARC4.new(rc4_key)
    return cipher.decrypt(data[12:60])


def _decrypt_des(data: bytes, key: bytes) -> bytes:
    plaintext = b""

    enc_size = unpack("<I", data[:4])[0]
    data = data[len(data) - enc_size :]

    key0 = key
    for _ in range(0, len(data), 8):
        ciphertext = data[:8]
        block_key = transform_key(key0[:7])

        cipher = DES.new(block_key, DES.MODE_ECB)
        plaintext += cipher.decrypt(ciphertext)

        key0 = key0[7:]
        data = data[8:]

        if len(key0) < 7:
            key0 = key[len(key0) :]

    return plaintext


def transform_key(key: bytes) -> bytes:
    # TODO: simplify this function
    new_key = []
    new_key.append(chr(ord(key[0:1]) >> 0x01))
    new_key.append(chr(((ord(key[0:1]) & 0x01) << 6) | (ord(key[1:2]) >> 2)))
    new_key.append(chr(((ord(key[1:2]) & 0x03) << 5) | (ord(key[2:3]) >> 3)))
    new_key.append(chr(((ord(key[2:3]) & 0x07) << 4) | (ord(key[3:4]) >> 4)))
    new_key.append(chr(((ord(key[3:4]) & 0x0F) << 3) | (ord(key[4:5]) >> 5)))
    new_key.append(chr(((ord(key[4:5]) & 0x1F) << 2) | (ord(key[5:6]) >> 6)))
    new_key.append(chr(((ord(key[5:6]) & 0x3F) << 1) | (ord(key[6:7]) >> 7)))
    new_key.append(chr(ord(key[6:7]) & 0x7F))

    for i in range(8):
        new_key[i] = chr((ord(new_key[i]) << 1) & 0xFE)

    return ("".join(new_key)).encode("latin-1")
