import re
from functools import cache, cached_property
from pathlib import Path
from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import InternalPlugin
from dissect.target.plugins.os.windows.dpapi.blob import Blob as DPAPIBlob
from dissect.target.plugins.os.windows.dpapi.master_key import CredSystem, MasterKeyFile
from dissect.target.target import Target


class DPAPIPlugin(InternalPlugin):
    """Windows Data Protection API (DPAPI) plugin.

    Resources:
        - Reversing ``Crypt32.dll``
        - https://learn.microsoft.com/en-us/windows/win32/api/dpapi/
        - https://github.com/fortra/impacket/blob/master/examples/dpapi.py
        - https://github.com/tijldeneut/DPAPIck3
        - https://www.passcape.com/index.php?section=docsys&cmd=details&id=28
    """

    __namespace__ = "dpapi"

    RE_MASTER_KEY = re.compile("^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
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
        """Returns dict of found DPAPI master keys on the Windows target for SYSTEM and regular users."""
        master_keys = {}

        # Search for SYSTEM master keys
        #
        # We assume there is no user named "System" as this username is reserved for the actual SYSTEM user.
        # https://support.microsoft.com/en-us/help/909264#table-of-reserved-words
        master_keys[self.SYSTEM_USERNAME] = {}

        system_master_key_path = self.target.fs.path("sysvol/Windows/System32/Microsoft/Protect/S-1-5-18")
        system_user_master_key_path = system_master_key_path.joinpath("User")

        for dir in [system_master_key_path, system_user_master_key_path]:
            user_mks = self._load_master_keys_from_path(self.SYSTEM_USERNAME, dir)
            master_keys[self.SYSTEM_USERNAME].update(user_mks)

        # Search for user master keys
        #
        # Generally located at $HOME/AppData/Roaming/Microsoft/Protect/{user_sid}/{mk_guid}
        PROTECT_DIRS = [
            # Windows Vista and newer
            "AppData/Roaming/Microsoft/Protect",
            # Windows XP
            "Application Data/Microsoft/Protect",
        ]

        # TODO: We should probably identify users with their SID instead of username.
        for user in self.target.user_details.all_with_home():
            master_keys.setdefault(user.user.name, {})

            for protect_dir in PROTECT_DIRS:
                path = user.home_path.joinpath(protect_dir).joinpath(user.user.sid)
                if user_mks := self._load_master_keys_from_path(user.user.name, path):
                    master_keys[user.user.name] |= user_mks

        return master_keys

    @cached_property
    def _users(self) -> dict[str, dict[str, str]]:
        return {u.name: {"sid": u.sid} for u in self.target.users()}

    def _load_master_keys_from_path(self, username: str, path: Path) -> Iterator[tuple[str, MasterKeyFile]]:
        """Iterate over the provided ``path`` and search for master key files for the given user."""

        if not path.exists():
            self.target.log.info(f"Unable to load master keys from path {path}: does not exist")
            return

        for file in path.iterdir():
            if not self.MASTER_KEY_REGEX.findall(file.name):
                continue

            with file.open() as fh:
                mkf = MasterKeyFile(fh)

            # Decrypt SYSTEM master key using the DPAPI_SYSTEM LSA secret.
            if username == self.SYSTEM_USERNAME:
                if "DPAPI_SYSTEM" not in self.target.lsa._secrets:
                    self.target.log.warning("Unable to decrypt SYSTEM master key: LSA secret missing")
                    continue

                # Windows XP
                if float(self.target.ntversion) < 6.0:
                    secret_offset = 8

                # Windows Vista and newer
                else:
                    secret_offset = 16

                dpapi_system = CredSystem(self.target.lsa._secrets["DPAPI_SYSTEM"][secret_offset:])
                mkf.decrypt_with_key(dpapi_system.machine_key)
                mkf.decrypt_with_key(dpapi_system.user_key)

                # Decrypting the System master key should always succeed
                if not mkf.decrypted:
                    self.target.log.error("Failed to decrypt SYSTEM master key!")
                    continue

                yield file.name, mkf

            # Decrypt user master key
            elif user := self._users.get(username):
                # Iterate over every master key password we have from the keychain
                for provider, mk_pass in self.keychain():
                    try:
                        if mkf.decrypt_with_password(user["sid"], mk_pass):
                            self.target.log.info(
                                f"Decrypted user master key with password '{mk_pass}' from provider {provider}"
                            )
                            break
                    except ValueError:
                        pass

                    try:
                        if mkf.decrypt_with_hash(user["sid"], bytes.fromhex(mk_pass)):
                            self.target.log.info(
                                f"Decrypted user master key with hash '{mk_pass}' from provider {provider}"
                            )
                            break
                    except ValueError:
                        pass

                if not mkf.decrypted:
                    self.target.log.warning(f"Could not decrypt master key '{file.name}' for username '{username}'")

                yield file.name, mkf

            else:
                self.target.log.warning(f"User does not exist on this target: {username}")

    def decrypt_system_blob(self, data: bytes) -> bytes:
        """Decrypt the given bytes using the SYSTEM master key."""
        return self.decrypt_user_blob(data, self.SYSTEM_USERNAME)

    def decrypt_user_blob(self, data: bytes, username: str) -> bytes:
        """Decrypt the given bytes using the master key of the given user."""
        try:
            blob = DPAPIBlob(data)
        except EOFError as e:
            raise ValueError(f"Failed to parse DPAPI blob: {e}")

        if not (mk := self.master_keys.get(username, {}).get(blob.guid)):
            raise ValueError(f"Blob is encrypted using master key {blob.guid} that we do not have for user {username}")

        if not blob.decrypt(mk.key):
            raise ValueError(f"Failed to decrypt blob for user {username}")

        return blob.clear_text

    def decrypt_blob(self, data: bytes) -> bytes:
        """Attempt to decrypt the given bytes using any of the available master keys."""
        try:
            blob = DPAPIBlob(data)
        except EOFError as e:
            raise ValueError(f"Failed to parse DPAPI blob: {e}")

        for user in self.master_keys:
            for mk in self.master_keys[user].values():
                if blob.decrypt(mk.key):
                    return blob.clear_text

        raise ValueError("Failed to decrypt blob using any available master key")
