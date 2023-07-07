import re
from struct import unpack
from typing import Optional
from functools import cached_property, lru_cache

from Crypto.Cipher import ARC4, AES, DES
from Crypto.Hash import MD5, SHA256


from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError, FileNotFoundError
from dissect.target.plugin import InternalPlugin
from dissect.target.plugins.os.windows.dpapi.blob import DPAPIBlob
from dissect.target.plugins.os.windows.dpapi.types.masterkey import CredSystem
from dissect.target.plugins.os.windows.dpapi.masterkey import MasterKeyFile


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

    @property
    def syskey(self) -> bytes:
        return self._retrieve_syskey()

    @lru_cache
    def _retrieve_syskey(self) -> bytes:
        lsa = self.target.registry.key(self.SYSTEM_KEY)
        syskey_keys = ["JD", "Skew1", "GBG", "Data"]
        # This magic value rotates the order of the data
        alterator = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3, 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]

        r = bytes.fromhex("".join([lsa.subkey(key).class_name for key in syskey_keys]))
        return bytes(r[i] for i in alterator)

    @lru_cache
    def _get_lsa_key(self):
        if self._newer_than_vista:
            policy_key = "PolEKList"
        else:
            policy_key = "PolSecretEncryptionKey"

        encrypted_key = (
            self.target.registry.key(self.SECURITY_KEY.format(KEY=policy_key)).value(self.DEFAULT_REG_VALUE).value
        )

        if self._newer_than_vista:
            lsa_key = self.__decrypt_aes(encrypted_key, self._retrieve_syskey())
            lsa_key = lsa_key[68:100]
        else:
            md5 = MD5.new()
            md5.update(self._retrieve_syskey())
            for _ in range(1000):
                md5.update(encrypted_key[60:76])
            rc4key = md5.digest()

            rc4 = ARC4.new(rc4key)
            lsa_key = rc4.decrypt(encrypted_key[12:60])
            lsa_key = lsa_key[16:32]
        return lsa_key

    @lru_cache
    def _secrets(self):
        secrets = self.target.registry.key(self.SECURITY_KEY.format(KEY="Secrets"))
        for subkey in secrets.subkeys():
            enc_data = subkey.subkey("CurrVal").value(self.DEFAULT_REG_VALUE).value
            if self._newer_than_vista:
                secret = self.__decrypt_aes(enc_data, self._get_lsa_key())
                yield (subkey.name, secret)
            else:
                secret = self.__decrypt_des(enc_data[0xC:], self._retrieve_syskey())
                yield (subkey.name, secret)

    @cached_property
    def secrets(self):
        return dict(list(self._secrets()))

    @classmethod
    def __decrypt_des(self, secret: bytes, key: bytes):
        decrypted_data = b""
        j = 0  # key index

        for i in range(0, len(secret), 8):
            enc_block = secret[i : i + 8]
            block_key = key[j : j + 7]
            des_key = self.__sidbytes_to_key(block_key)
            des = DES.new(des_key, DES.MODE_ECB)
            enc_block = enc_block + b"\x00" * int(abs(8 - len(enc_block)) % 8)
            decrypted_data += des.decrypt(enc_block)  # lgtm [py/weak-cryptographic-algorithm]
            j += 7
            if len(key[j : j + 7]) < 7:
                j = len(key[j : j + 7])

        (dec_data_len,) = unpack("<L", decrypted_data[:4])

        return decrypted_data[8 : 8 + dec_data_len]

    @staticmethod
    def __sidbytes_to_key(s: bytes) -> bytes:
        # fmt: off
        odd_parity = [1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14, 16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31, 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47, 49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62, 64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79, 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94, 97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110, 112, 112, 115, 115, 117, 117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133, 133, 134, 134, 137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158, 161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174, 176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191, 193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206, 208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223, 224, 224, 227, 227, 229, 229, 230, 230, 233, 233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247, 247, 248, 248, 251, 251, 253, 253, 254, 254] # noqa
        # fmt: on
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

    @staticmethod
    def __decrypt_aes(encrypted_data: bytes, key: bytes) -> bytes:
        sha = SHA256.new()
        sha.update(key)
        for _ in range(1, 1000 + 1):
            sha.update(encrypted_data[28:60])
        aeskey = sha.digest()

        data = b""
        for i in range(60, len(encrypted_data), 16):
            aes = AES.new(aeskey, AES.MODE_CBC, b"\x00" * 16)
            buf = encrypted_data[i : i + 16]
            if len(buf) < 16:
                buf += (16 - len(buf)) * "\00"
            data += aes.decrypt(buf)

        return data

    @lru_cache
    def _get_master_keys(self) -> dict[str, dict[str, MasterKeyFile]]:
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
                    mkf.decryptWithKey(dpapi_system.pMachine)
                    if not mkf.decrypted:
                        mkf.decryptWithKey(dpapi_system.pUser)
                    # This should not be possible, decrypting the System masterkey should always succeed
                    if not mkf.decrypted:
                        raise Exception("Failed to decrypt System masterkey")
                curr_masterkeys[masterkey.name] = mkf
        return curr_masterkeys

    def dpapi_system(self) -> CredSystem:
        return CredSystem.read(self.secrets["DPAPI_SYSTEM"][16:])

    def decrypt_dpapi_system_blob(self, data: bytes) -> Optional[DPAPIBlob]:
        blob = DPAPIBlob(data)
        mk = self._get_master_keys().get(self.SYSTEM_USERNAME, {}).get(blob.mkguid)
        if not mk:
            return None
        if blob.decrypt(mk.get_key()):
            return blob
        return None
