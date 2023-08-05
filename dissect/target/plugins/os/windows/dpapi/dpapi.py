import hashlib
import re
from functools import cached_property, lru_cache
from struct import unpack
from typing import Optional

from Crypto.Cipher import AES, ARC4, DES

from dissect.target import Target
from dissect.target.exceptions import FileNotFoundError, UnsupportedPluginError
from dissect.target.plugin import InternalPlugin
from dissect.target.plugins.os.windows.dpapi.blob import Blob as DPAPIBlob
from dissect.target.plugins.os.windows.dpapi.masterkey import MasterKeyFile
from dissect.target.plugins.os.windows.dpapi.types.masterkey import CredSystem


class DPAPIPlugin(InternalPlugin):
    __namespace__ = "dpapi"

    # This matches master_key file names
    MASTER_KEY_REGEX = re.compile("^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    DEFAULT_REG_VALUE = "(Default)"
    SECURITY_KEY = "HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\{KEY}"
    SYSTEM_KEY = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA"
    SYSTEM_USERNAME = "System"

    SYSTEM_MASTER_KEY_PATH = "sysvol/Windows/System32/Microsoft/Protect/S-1-5-18"
    SYSTEM_USER_MASTER_KEY_PATH = f"{SYSTEM_MASTER_KEY_PATH}/User"
    USER_MASTER_KEY_PATH = "AppData/Roaming/Microsoft/Protect"

    def __init__(self, target: Target):
        super().__init__(target)

        # Some calculations are different pre Vista
        os_version = self.target._os._nt_version()
        # This can happen during testing, not sure how to solve in a better way
        if not os_version:
            os_version = 99999
        self._newer_than_vista: float = float(os_version) >= 6.0

    def check_compatible(self) -> bool:
        if not list(self.target.registry.keys(self.SYSTEM_KEY)):
            raise UnsupportedPluginError(f"Registry key not found: {self.SYSTEM_KEY}")

        return True

    @cached_property
    def syskey(self) -> bytes:
        lsa = self.target.registry.key(self.SYSTEM_KEY)
        syskey_keys = ["JD", "Skew1", "GBG", "Data"]
        # This magic value rotates the order of the data
        alterator = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]

        r = bytes.fromhex("".join([lsa.subkey(key).class_name for key in syskey_keys]))
        return bytes(r[i] for i in alterator)

    @lru_cache
    def _get_lsa_key(self) -> bytes:
        if self._newer_than_vista:
            policy_key = "PolEKList"
        else:
            policy_key = "PolSecretEncryptionKey"

        encrypted_key = (
            self.target.registry.key(self.SECURITY_KEY.format(KEY=policy_key)).value(self.DEFAULT_REG_VALUE).value
        )

        if self._newer_than_vista:
            lsa_key = _decrypt_aes(encrypted_key, self.syskey)
            lsa_key = lsa_key[68:100]
        else:
            md5 = hashlib.md5()
            md5.update(self.syskey)
            for _ in range(1000):
                md5.update(encrypted_key[60:76])
            rc4key = md5.digest()

            rc4 = ARC4.new(rc4key)
            lsa_key = rc4.decrypt(encrypted_key[12:60])
            lsa_key = lsa_key[16:32]
        return lsa_key

    @cached_property
    def secrets(self) -> dict[str, bytes]:
        res = {}
        reg_secrets = self.target.registry.key(self.SECURITY_KEY.format(KEY="Secrets"))
        for subkey in reg_secrets.subkeys():
            enc_data = subkey.subkey("CurrVal").value(self.DEFAULT_REG_VALUE).value
            if self._newer_than_vista:
                secret = _decrypt_aes(enc_data, self._get_lsa_key())
            else:
                secret = __decrypt_des(enc_data[0xC:], self.syskey)
            res[subkey.name] = secret
        return res

    @cached_property
    def master_keys(self) -> dict[str, dict[str, MasterKeyFile]]:
        # This assumes that there is no user named System.
        # As far as I can tell, the name "System" is saved for the actual System user
        # Therefore the user can't actually exist in `all_with_home`
        user_masterkeys = {self.SYSTEM_USERNAME: {}}
        for dir in [self.SYSTEM_MASTER_KEY_PATH, self.SYSTEM_USER_MASTER_KEY_PATH]:
            user_mks = self.load_masterkeys_from_path(
                self.SYSTEM_USERNAME,
                dir,
            )
            user_masterkeys[self.SYSTEM_USERNAME].update(user_mks)

        for user in self.target.user_details.all_with_home():
            user_mks = self.load_masterkeys_from_path(
                user.user.name,
                user.home_path.joinpath(self.USER_MASTER_KEY_PATH).joinpath(user.user.sid).as_posix(),
            )
            if user_mks:
                user_masterkeys[user.user.name] = user_mks

        return user_masterkeys

    def load_masterkeys_from_path(self, username: str, protect_dir: str) -> dict[str, MasterKeyFile]:
        try:
            files = self.target.fs.listdir_ext(protect_dir)
        except FileNotFoundError:
            return {}

        curr_masterkeys = {}
        for masterkey in files:
            if self.MASTER_KEY_REGEX.findall(masterkey.name):
                with masterkey.open() as m:
                    mkf = MasterKeyFile()
                    mkf.read(m)
                if username == self.SYSTEM_USERNAME:
                    dpapi_system = self.dpapi_system()
                    mkf.decrypt_with_key(dpapi_system.pMachine)
                    if not mkf.decrypted:
                        mkf.decrypt_with_key(dpapi_system.pUser)
                    # This should not be possible, decrypting the System masterkey should always succeed
                    if not mkf.decrypted:
                        raise Exception("Failed to decrypt System masterkey")
                curr_masterkeys[masterkey.name] = mkf
        return curr_masterkeys

    @lru_cache
    def dpapi_system(self) -> CredSystem:
        return CredSystem.read(self.secrets["DPAPI_SYSTEM"][16:])

    def decrypt_dpapi_system_blob(self, data: bytes) -> Optional[DPAPIBlob]:
        blob = DPAPIBlob(data)
        mk = self.master_keys.get(self.SYSTEM_USERNAME, {}).get(blob.mkguid)
        if not mk:
            return None
        if blob.decrypt(mk.key):
            return blob
        return None


def __decrypt_des(secret: bytes, key: bytes) -> bytes:
    decrypted_data = b""
    j = 0  # key index

    for i in range(0, len(secret), 8):
        enc_block = secret[i : i + 8]
        block_key = key[j : j + 7]
        des_key = __sidbytes_to_key(block_key)
        des = DES.new(des_key, DES.MODE_ECB)
        enc_block = enc_block + b"\x00" * int(abs(8 - len(enc_block)) % 8)
        decrypted_data += des.decrypt(enc_block)  # lgtm [py/weak-cryptographic-algorithm]
        j += 7
        if len(key[j : j + 7]) < 7:
            j = len(key[j : j + 7])

    (dec_data_len,) = unpack("<L", decrypted_data[:4])

    return decrypted_data[8 : 8 + dec_data_len]


def __sidbytes_to_key(s: bytes) -> bytes:
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


def _decrypt_aes(encrypted_data: bytes, key: bytes) -> bytes:
    sha = hashlib.sha256()
    sha.update(key)
    for _ in range(1, 1000 + 1):
        sha.update(encrypted_data[28:60])
    aeskey = sha.digest()

    data = b""
    for i in range(60, len(encrypted_data), 16):
        aes = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16)
        buf = encrypted_data[i : i + 16]
        if len(buf) < 16:
            buf += (16 - len(buf)) * b"\00"
        data += aes.decrypt(buf)

    return data
