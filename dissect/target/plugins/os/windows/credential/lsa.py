from __future__ import annotations

import hashlib
from functools import cached_property
from typing import Iterator

from dissect.target.exceptions import RegistryKeyNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

try:
    from Crypto.Cipher import AES, ARC4, DES

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


LSASecretRecord = TargetRecordDescriptor(
    "windows/credential/lsa",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "value"),
    ],
)


class LSAPlugin(Plugin):
    """Windows Local Security Authority (LSA) plugin.

    Resources:
        - https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication
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

        try:
            # Windows Vista or newer
            enc_key = security_pol.subkey("PolEKList").value("(Default)").value
            lsa_key = _decrypt_aes(enc_key, self.syskey)
            return lsa_key[68:100]
        except RegistryKeyNotFoundError:
            pass

        try:
            # Windows XP
            enc_key = security_pol.subkey("PolSecretEncryptionKey").value("(Default)").value
            lsa_key = _decrypt_rc4(enc_key, self.syskey)
            return lsa_key[16:32]
        except RegistryKeyNotFoundError:
            pass

        raise ValueError("Unable to determine LSA policy key location in registry")

    @cached_property
    def _secrets(self) -> dict[str, bytes] | None:
        """Return dict of Windows system decrypted LSA secrets."""
        if not self.target.ntversion:
            raise ValueError("Unable to determine Windows NT version")

        result = {}
        for subkey in self.target.registry.key(self.SECURITY_POLICY_KEY).subkey("Secrets").subkeys():
            enc_data = subkey.subkey("CurrVal").value("(Default)").value

            # Windows Vista or newer
            if float(self.target.ntversion) >= 6.0:
                secret = _decrypt_aes(enc_data, self.lsakey)

            # Windows XP
            else:
                secret = _decrypt_des(enc_data, self.lsakey)

            result[subkey.name] = secret

        return result

    @export(record=LSASecretRecord)
    def secrets(self) -> Iterator[LSASecretRecord]:
        """Yield decrypted LSA secrets from a Windows target."""
        for key, value in self._secrets.items():
            yield LSASecretRecord(
                ts=self.target.registry.key(f"{self.SECURITY_POLICY_KEY}\\Secrets\\{key}").ts,
                name=key,
                value=value.hex(),
                _target=self.target,
            )


def _decrypt_aes(data: bytes, key: bytes) -> bytes:
    ctx = hashlib.sha256()
    ctx.update(key)
    for _ in range(1, 1000 + 1):
        ctx.update(data[28:60])

    ciphertext = data[60:]
    plaintext = []

    for i in range(0, len(ciphertext), 16):
        cipher = AES.new(ctx.digest(), AES.MODE_CBC, iv=b"\x00" * 16)
        plaintext.append(cipher.decrypt(ciphertext[i : i + 16].ljust(16, b"\x00")))

    return b"".join(plaintext)


def _decrypt_rc4(data: bytes, key: bytes) -> bytes:
    md5 = hashlib.md5()
    md5.update(key)
    for _ in range(1000):
        md5.update(data[60:76])
    rc4_key = md5.digest()

    cipher = ARC4.new(rc4_key)
    return cipher.decrypt(data[12:60])


def _decrypt_des(data: bytes, key: bytes) -> bytes:
    plaintext = []

    enc_size = int.from_bytes(data[:4], "little")
    data = data[len(data) - enc_size :]

    key0 = key
    for _ in range(0, len(data), 8):
        ciphertext = data[:8]
        block_key = _transform_key(key0[:7])

        cipher = DES.new(block_key, DES.MODE_ECB)
        plaintext.append(cipher.decrypt(ciphertext))

        key0 = key0[7:]
        data = data[8:]

        if len(key0) < 7:
            key0 = key[len(key0) :]

    return b"".join(plaintext)


def _transform_key(key: bytes) -> bytes:
    new_key = []
    new_key.append(((key[0] >> 0x01) << 1) & 0xFE)
    for i in range(0, 6):
        new_key.append((((key[i] & ((1 << (i + 1)) - 1)) << (6 - i) | (key[i + 1] >> (i + 2))) << 1) & 0xFE)
    new_key.append(((key[6] & 0x7F) << 1) & 0xFE)
    return bytes(new_key)
