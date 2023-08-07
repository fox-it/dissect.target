import hashlib
import re
from functools import cached_property
from pathlib import Path

from Crypto.Cipher import AES, ARC4, DES

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import InternalPlugin
from dissect.target.plugins.os.windows.dpapi.blob import Blob as DPAPIBlob
from dissect.target.plugins.os.windows.dpapi.master_key import CredSystem, MasterKeyFile


class DPAPIPlugin(InternalPlugin):
    __namespace__ = "dpapi"

    # This matches master key file names
    MASTER_KEY_REGEX = re.compile("^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")

    SECURITY_POLICY_KEY = "HKEY_LOCAL_MACHINE\\SECURITY\\Policy"
    SYSTEM_KEY = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA"

    SYSTEM_USERNAME = "System"

    def __init__(self, target: Target):
        super().__init__(target)

        # Some calculations are different pre Vista
        ntversion = self.target.ntversion
        # This can happen during testing, not sure how to solve in a better way
        if not ntversion:
            ntversion = 99999
        self._vista_or_newer = float(ntversion) >= 6.0

    def check_compatible(self) -> None:
        if not list(self.target.registry.keys(self.SYSTEM_KEY)):
            raise UnsupportedPluginError(f"Registry key not found: {self.SYSTEM_KEY}")

    @cached_property
    def syskey(self) -> bytes:
        lsa = self.target.registry.key(self.SYSTEM_KEY)
        syskey_keys = ["JD", "Skew1", "GBG", "Data"]
        # This magic value rotates the order of the data
        alterator = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]

        r = bytes.fromhex("".join([lsa.subkey(key).class_name for key in syskey_keys]))
        return bytes(r[i] for i in alterator)

    @cached_property
    def lsakey(self) -> bytes:
        if self._vista_or_newer:
            policy_key = "PolEKList"
        else:
            policy_key = "PolSecretEncryptionKey"

        encrypted_key = self.target.registry.key(self.SECURITY_POLICY_KEY).subkey(policy_key).value("(Default)").value

        if self._vista_or_newer:
            lsa_key = _decrypt_aes(encrypted_key, self.syskey)
            lsa_key = lsa_key[68:100]
        else:
            ctx = hashlib.md5()
            ctx.update(self.syskey)

            tmp = encrypted_key[60:76]
            for _ in range(1000):
                ctx.update(tmp)

            cipher = ARC4.new(ctx.digest())
            lsa_key = cipher.decrypt(encrypted_key[12:60])
            lsa_key = lsa_key[16:32]

        return lsa_key

    @cached_property
    def secrets(self) -> dict[str, bytes]:
        result = {}

        reg_secrets = self.target.registry.key(self.SECURITY_POLICY_KEY).subkey("Secrets")
        for subkey in reg_secrets.subkeys():
            enc_data = subkey.subkey("CurrVal").value("(Default)").value
            if self._vista_or_newer:
                secret = _decrypt_aes(enc_data, self.lsakey)
            else:
                secret = _decrypt_des(enc_data[12:], self.syskey)
            result[subkey.name] = secret

        return result

    @cached_property
    def master_keys(self) -> dict[str, dict[str, MasterKeyFile]]:
        # This assumes that there is no user named System.
        # As far as I can tell, the name "System" is saved for the actual System user
        # Therefore the user can't actually exist in `all_with_home`
        result = {"System": {}}

        system_master_key_path = self.target.fs.path("sysvol/Windows/System32/Microsoft/Protect/S-1-5-18")
        system_user_master_key_path = system_master_key_path.joinpath("User")

        for dir in [system_master_key_path, system_user_master_key_path]:
            user_mks = self._load_master_keys_from_path(self.SYSTEM_USERNAME, dir)
            result[self.SYSTEM_USERNAME].update(user_mks)

        for user in self.target.user_details.all_with_home():
            path = user.home_path.joinpath("AppData/Roaming/Microsoft/Protect").joinpath(user.user.sid)
            user_mks = self._load_master_keys_from_path(user.user.name, path)
            if user_mks:
                result[user.user.name] = user_mks

        return result

    def _load_master_keys_from_path(self, username: str, path: Path) -> dict[str, MasterKeyFile]:
        if not path.exists():
            return {}

        result = {}
        for file in path.iterdir():
            if self.MASTER_KEY_REGEX.findall(file.name):
                with file.open() as fh:
                    mkf = MasterKeyFile(fh)

                if username == self.SYSTEM_USERNAME:
                    dpapi_system = CredSystem(self.secrets["DPAPI_SYSTEM"][16:])

                    if not mkf.decrypt_with_key(dpapi_system.machine_key):
                        mkf.decrypt_with_key(dpapi_system.user_key)

                    # This should not be possible, decrypting the System master key should always succeed
                    if not mkf.decrypted:
                        raise Exception("Failed to decrypt System master key")

                result[file.name] = mkf

        return result

    def decrypt_system_blob(self, data: bytes) -> bytes:
        blob = DPAPIBlob(data)

        if not (mk := self.master_keys.get(self.SYSTEM_USERNAME, {}).get(blob.guid)):
            raise ValueError("Blob UUID is unknown to system master keys")

        if not blob.decrypt(mk.key):
            raise ValueError("Failed to decrypt system blob")

        return blob.clear_text


def _decrypt_aes(data: bytes, key: bytes) -> bytes:
    ctx = hashlib.sha256()
    ctx.update(key)

    tmp = data[28:60]
    for _ in range(1, 1000 + 1):
        ctx.update(tmp)

    aeskey = ctx.digest()
    iv = b"\x00" * 16

    result = []
    for i in range(60, len(data), 16):
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        result.append(cipher.decrypt(data[i : i + 16].ljust(16, b"\x00")))

    return b"".join(result)


def _decrypt_des(secret: bytes, key: bytes) -> bytes:
    result = []

    j = 0  # key index
    for i in range(0, len(secret), 8):
        enc_block = secret[i : i + 8]
        block_key = key[j : j + 7]
        des_key = _sid_bytes_to_key(block_key)

        cipher = DES.new(des_key, DES.MODE_ECB)
        enc_block = enc_block + b"\x00" * int(abs(8 - len(enc_block)) % 8)
        result.append(cipher.decrypt(enc_block))  # lgtm [py/weak-cryptographic-algorithm]

        j += 7
        if len(key[j : j + 7]) < 7:
            j = len(key[j : j + 7])

    decrypted = b"".join(result)
    decrypted_len = int.from_bytes(decrypted[:4], "little")

    return decrypted[8 : 8 + decrypted_len]


def _sid_bytes_to_key(s: bytes) -> bytes:
    odd_parity = b"\x01\x01\x02\x02\x04\x04\x07\x07\x08\x08\x0b\x0b\r\r\x0e\x0e\x10\x10\x13\x13\x15\x15\x16\x16\x19\x19\x1a\x1a\x1c\x1c\x1f\x1f  ##%%&&))**,,//1122447788;;==>>@@CCEEFFIIJJLLOOQQRRTTWWXX[[]]^^aabbddgghhkkmmnnppssuuvvyyzz||\x7f\x7f\x80\x80\x83\x83\x85\x85\x86\x86\x89\x89\x8a\x8a\x8c\x8c\x8f\x8f\x91\x91\x92\x92\x94\x94\x97\x97\x98\x98\x9b\x9b\x9d\x9d\x9e\x9e\xa1\xa1\xa2\xa2\xa4\xa4\xa7\xa7\xa8\xa8\xab\xab\xad\xad\xae\xae\xb0\xb0\xb3\xb3\xb5\xb5\xb6\xb6\xb9\xb9\xba\xba\xbc\xbc\xbf\xbf\xc1\xc1\xc2\xc2\xc4\xc4\xc7\xc7\xc8\xc8\xcb\xcb\xcd\xcd\xce\xce\xd0\xd0\xd3\xd3\xd5\xd5\xd6\xd6\xd9\xd9\xda\xda\xdc\xdc\xdf\xdf\xe0\xe0\xe3\xe3\xe5\xe5\xe6\xe6\xe9\xe9\xea\xea\xec\xec\xef\xef\xf1\xf1\xf2\xf2\xf4\xf4\xf7\xf7\xf8\xf8\xfb\xfb\xfd\xfd\xfe\xfe"  # noqa

    key = [
        s[0] >> 1,
        ((s[0] & 0x01) << 6) | (s[1] >> 2),
        ((s[1] & 0x03) << 5) | (s[2] >> 3),
        ((s[2] & 0x07) << 4) | (s[3] >> 4),
        ((s[3] & 0x0F) << 3) | (s[4] >> 5),
        ((s[4] & 0x1F) << 2) | (s[5] >> 6),
        ((s[5] & 0x3F) << 1) | (s[6] >> 7),
        s[6] & 0x7F,
    ]

    for i in range(8):
        key[i] = key[i] << 1
        key[i] = odd_parity[key[i]]

    return bytes(key)
