import re
from functools import cache, cached_property
from pathlib import Path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import InternalPlugin
from dissect.target.plugins.os.windows.dpapi.blob import Blob as DPAPIBlob
from dissect.target.plugins.os.windows.dpapi.master_key import CredSystem, MasterKeyFile
from dissect.target.target import Target


class DPAPIPlugin(InternalPlugin):
    __namespace__ = "dpapi"

    MASTER_KEY_REGEX = re.compile("^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    SYSTEM_USERNAME = "System"

    def __init__(self, target: Target):
        super().__init__(target)
        self.keychain = cache(self.keychain)

    def check_compatible(self) -> None:
        if not self.target.has_function("lsa"):
            raise UnsupportedPluginError("Windows registry and LSA plugins are required for DPAPI decryption")

    def keychain(self) -> set:
        return set(self.target.dpapi_keyprovider.keys())

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

        PROTECT_DIRS = [
            # Windows Vista and newer
            "AppData/Roaming/Microsoft/Protect",
            # Windows XP
            "Application Data/Microsoft/Protect",
        ]

        for user in self.target.user_details.all_with_home():
            for protect_dir in PROTECT_DIRS:
                path = user.home_path.joinpath(protect_dir).joinpath(user.user.sid)
                user_mks = self._load_master_keys_from_path(user.user.name, path)
                if user_mks:
                    result[user.user.name] = user_mks

        return result

    @cached_property
    def _users(self) -> dict[str, dict[str, str]]:
        return {u.name: {"sid": u.sid} for u in self.target.users()}

    def _load_master_keys_from_path(self, username: str, path: Path) -> dict[str, MasterKeyFile]:
        if not path.exists():
            return {}

        result = {}
        for file in path.iterdir():
            if self.MASTER_KEY_REGEX.findall(file.name):
                with file.open() as fh:
                    mkf = MasterKeyFile(fh)

                # Decrypt SYSTEM master key
                if username == self.SYSTEM_USERNAME:
                    # Windows XP
                    if float(self.target._os._nt_version()) < 6.0:
                        secret_offset = 8

                    # Windows Vista and newer
                    else:
                        secret_offset = 16

                    dpapi_system = CredSystem(self.target.lsa.secrets["DPAPI_SYSTEM"][secret_offset:])

                    if not mkf.decrypt_with_key(dpapi_system.machine_key):
                        mkf.decrypt_with_key(dpapi_system.user_key)

                    # This should not be possible, decrypting the System master key should always succeed
                    if not mkf.decrypted:
                        raise Exception("Failed to decrypt System master key")

                # Decrypt user master key
                if user := self._users.get(username):
                    for provider, mk_pass in self.keychain():
                        if mkf.decrypt_with_password(user["sid"], mk_pass):
                            break

                        try:
                            if mkf.decrypt_with_hash(user["sid"], bytes.fromhex(mk_pass)) is True:
                                break
                        except ValueError:
                            pass

                    if not mkf.decrypted:
                        self.target.log.warning("Could not decrypt DPAPI master key for username '%s'", username)

                result[file.name] = mkf

        return result

    def decrypt_system_blob(self, data: bytes) -> bytes:
        """Decrypt the given bytes using the System master key."""
        return self.decrypt_user_blob(data, self.SYSTEM_USERNAME)

    def decrypt_user_blob(self, data: bytes, username: str) -> bytes:
        """Decrypt the given bytes using the master key of the given user."""
        blob = DPAPIBlob(data)

        if not (mk := self.master_keys.get(username, {}).get(blob.guid)):
            raise ValueError(f"Blob UUID is unknown to {username} master keys")

        if not blob.decrypt(mk.key):
            raise ValueError(f"Failed to decrypt blob for user {username}")

        return blob.clear_text

    def decrypt_blob(self, data: bytes) -> bytes:
        """Attempt to decrypt the given bytes using any of the available master keys."""
        blob = DPAPIBlob(data)

        for user in self.master_keys:
            for mk in self.master_keys[user].values():
                if blob.decrypt(mk.key):
                    return blob.clear_text

        raise ValueError("Failed to decrypt blob")
