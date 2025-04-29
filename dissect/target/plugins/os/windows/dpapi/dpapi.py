from __future__ import annotations

import re
from functools import cache, cached_property
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import InternalPlugin
from dissect.target.plugins.os.windows.dpapi.blob import Blob as DPAPIBlob
from dissect.target.plugins.os.windows.dpapi.master_key import CredSystem, MasterKeyFile

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

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
    SYSTEM_SID = "S-1-5-18"

    def __init__(self, target: Target):
        super().__init__(target)
        self.keychain = cache(self.keychain)

    def check_compatible(self) -> None:
        if not self.target.has_function("lsa"):
            raise UnsupportedPluginError("Windows registry and LSA plugins are required for DPAPI decryption")

    def keychain(self) -> set:
        return set(self.target._dpapi_keyprovider.keys())

    @cached_property
    def master_keys(self) -> dict[str, dict[str, MasterKeyFile]]:
        """Returns dict of found DPAPI master keys on the Windows target for SYSTEM and regular users."""
        master_keys = {}

        # Search for SYSTEM master keys
        master_keys[self.SYSTEM_SID] = {}

        system_master_key_path = self.target.fs.path(f"sysvol/Windows/System32/Microsoft/Protect/{self.SYSTEM_SID}")
        system_user_master_key_path = system_master_key_path.joinpath("User")

        for dir in [system_master_key_path, system_user_master_key_path]:
            user_mks = self._load_master_keys_from_path(self.SYSTEM_SID, dir)
            master_keys[self.SYSTEM_SID].update(user_mks)

        # Search for user master keys, generally located at $HOME/AppData/Roaming/Microsoft/Protect/{user_sid}/{mk_guid}
        PROTECT_DIRS = [
            # Windows Vista and newer
            "AppData/Roaming/Microsoft/Protect",
            # Windows XP
            "Application Data/Microsoft/Protect",
        ]

        for user in self.target.user_details.all_with_home():
            sid = user.user.sid
            master_keys.setdefault(sid, {})

            for protect_dir in PROTECT_DIRS:
                path = user.home_path.joinpath(protect_dir).joinpath(sid)
                if user_mks := self._load_master_keys_from_path(sid, path):
                    master_keys[sid] |= user_mks

        return master_keys

    def _load_master_keys_from_path(self, sid: str, path: Path) -> Iterator[tuple[str, MasterKeyFile]]:
        """Iterate over the provided ``path`` and search for master key files for the given user SID."""

        if not path.exists():
            self.target.log.info("Unable to load master keys from path as it does not exist: %s", path)
            return

        for file in path.iterdir():
            if not self.RE_MASTER_KEY.findall(file.name):
                continue

            with file.open() as fh:
                mkf = MasterKeyFile(fh)

            # Decrypt SYSTEM master key using the DPAPI_SYSTEM LSA secret.
            if sid == self.SYSTEM_SID:
                if "DPAPI_SYSTEM" not in self.target.lsa._secrets:
                    self.target.log.warning("Unable to decrypt SYSTEM master key: LSA secret missing")
                    continue

                # Windows XP or Windows Vista and newer
                secret_offset = 8 if float(self.target.ntversion) < 6.0 else 16

                dpapi_system = CredSystem(self.target.lsa._secrets["DPAPI_SYSTEM"][secret_offset:])
                mkf.decrypt_with_key(dpapi_system.machine_key)
                mkf.decrypt_with_key(dpapi_system.user_key)

                # Decrypting the System master key should always succeed
                if not mkf.decrypted:
                    self.target.log.error("Failed to decrypt SYSTEM master key!")
                    continue

                yield file.name, mkf

            # Decrypt user master key
            else:
                # Iterate over every master key password we have from the keychain
                for provider, mk_pass in self.keychain():
                    try:
                        if mkf.decrypt_with_password(sid, mk_pass):
                            self.target.log.info(
                                "Decrypted user master key with password '%s' from provider %s", mk_pass, provider
                            )
                            break
                    except ValueError:
                        pass

                    try:
                        if mkf.decrypt_with_hash(sid, bytes.fromhex(mk_pass)):
                            self.target.log.info(
                                "Decrypted SID %s master key with hash '%s' from provider %s", sid, mk_pass, provider
                            )
                            break
                    except ValueError:
                        pass

                if not mkf.decrypted:
                    self.target.log.warning("Could not decrypt master key '%s' for SID '%s'", file.name, sid)

                yield file.name, mkf

    @cached_property
    def _users(self) -> dict[str, str]:
        """Cached map of username to SID."""
        return {user.name: user.sid for user in self.target.users()}

    def decrypt_system_blob(self, data: bytes, **kwargs) -> bytes:
        """Decrypt the given bytes using the SYSTEM master key.

        Args:
            data: Bytes of DPAPI system blob to decrypt.
            **kwargs: Arbitrary named arguments to pass to :meth:`DPAPIBlob.decrypt <dissect.target.plugins.os.windows.dpapi.blob.Blob.decrypt>` function.

        Raises:
            ValueError: When conditions to decrypt are not met or if decrypting failed.

        Returns:
            Decrypted bytes.
        """  # noqa: E501
        return self.decrypt_user_blob(data, sid=self.SYSTEM_SID, **kwargs)

    def decrypt_user_blob(self, data: bytes, username: str | None = None, sid: str | None = None, **kwargs) -> bytes:
        """Decrypt the given bytes using the master key of the given SID or username.

        Args:
            data: Bytes of DPAPI blob to decrypt.
            username: Username of the owner of the DPAPI blob.
            sid: SID of the owner of the DPAPI blob.
            **kwargs: Arbitrary named arguments to pass to :meth:`DPAPIBlob.decrypt <dissect.target.plugins.os.windows.dpapi.blob.Blob.decrypt>` function.

        Raises:
            ValueError: When conditions to decrypt are not met or if decrypting failed.

        Returns:
            Decrypted bytes.
        """  # noqa: E501

        if not sid and not username:
            raise ValueError("Either sid or username argument is required")

        if not sid and username:
            sid = self._users.get(username)

        if not sid:
            raise ValueError("No SID provided or no SID found")

        try:
            blob = DPAPIBlob(data)
        except EOFError as e:
            raise ValueError(f"Failed to parse DPAPI blob: {e}")

        if not (mk := self.master_keys.get(sid, {}).get(blob.guid)):
            raise ValueError(f"Blob is encrypted using master key {blob.guid} that we do not have for SID {sid}")

        if not blob.decrypt(mk.key, **kwargs):
            raise ValueError(f"Failed to decrypt blob for SID {sid}")

        return blob.clear_text

    def decrypt_blob(self, data: bytes, **kwargs) -> bytes:
        """Attempt to decrypt the given bytes using any of the available master keys.

        Args:
            data: Bytes of DPAPI blob to decrypt.
            **kwargs: Arbitrary named arguments to pass to :meth:`DPAPIBlob.decrypt <dissect.target.plugins.os.windows.dpapi.blob.Blob.decrypt>` function.

        Raises:
            ValueError: When conditions to decrypt are not met or if decrypting failed.

        Returns:
            Decrypted bytes.
        """  # noqa: E501
        try:
            blob = DPAPIBlob(data)
        except EOFError as e:
            raise ValueError(f"Failed to parse DPAPI blob: {e}")

        for user in self.master_keys:
            for mk in self.master_keys[user].values():
                if blob.decrypt(mk.key, **kwargs):
                    return blob.clear_text

        raise ValueError("Failed to decrypt blob using any available master key")
