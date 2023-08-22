import hashlib
import re
from functools import cached_property
from pathlib import Path

from Crypto.Cipher import AES

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
        policy_key = "PolEKList"

        encrypted_key = self.target.registry.key(self.SECURITY_POLICY_KEY).subkey(policy_key).value("(Default)").value

        lsa_key = _decrypt_aes(encrypted_key, self.syskey)

        return lsa_key[68:100]

    @cached_property
    def secrets(self) -> dict[str, bytes]:
        result = {}

        reg_secrets = self.target.registry.key(self.SECURITY_POLICY_KEY).subkey("Secrets")
        for subkey in reg_secrets.subkeys():
            enc_data = subkey.subkey("CurrVal").value("(Default)").value
            secret = _decrypt_aes(enc_data, self.lsakey)
            result[subkey.name] = secret

        return result

    @cached_property
    def master_keys(self) -> dict[str, dict[str, MasterKeyFile]]:
        # This assumes that there is no user named System.
        # As far as I can tell, the name "System" is saved for the actual System user
        # Therefore the user can't actually exist in `all_with_home`
        result = {self.SYSTEM_USERNAME: {}}

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
