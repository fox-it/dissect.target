from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.cng.key import CNGKey

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


CNGKeyRecord = TargetRecordDescriptor(
    "windows/cng/key",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("path", "source"),
    ],
)


class CNGPlugin(Plugin):
    """Microsoft Windows Cryptography API Next Generation (CNG) plugin.

    Provides a modern and unified method for applications to perform key management, encryption,
    decryption, digital signing and hashing. It's purpose is to eventually replace the Windows
    Crypto API (CAPI).

    References:
        - ``bcrypt.dll`` (userland API)
        - ``ncrypt.dll`` (key storage and management)
        - https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval
        - https://learn.microsoft.com/en-us/windows/win32/seccng/cng-structures
        - https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_crypto_ngc.h
        - https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/ngc/kuhl_m_ngc.h
    """

    __namespace__ = "cng"

    SYSTEM_KEYS = ("sysvol\\ProgramData\\Microsoft\\Crypto\\SystemKeys",)

    USER_KEYS = ("AppData\\Roaming\\Microsoft\\Crypto\\Keys",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.system_keys = list(self._iter_keys(self.SYSTEM_KEYS))
        self.user_keys = list(self._iter_keys(self.USER_KEYS, True))
        self.all_keys = self.system_keys + self.user_keys

    def check_compatible(self) -> None:
        if not self.system_keys and not self.user_keys:
            raise UnsupportedPluginError("No CNG keys found on target")

    def _iter_keys(self, path_strs: Iterator[str], users: bool = False) -> Iterator[CNGKey]:
        """Search for system or user keys in the provided locations."""
        for path_str in path_strs:
            if users:
                for user_details in self.target.user_details.all_with_home():
                    if (dir := user_details.home_path.joinpath(path_str)).is_dir():
                        for file in dir.iterdir():
                            yield CNGKey(self.target, file, user_details.user.sid)

            elif (dir := self.target.fs.path(path_str)).is_dir():
                for file in dir.iterdir():
                    yield CNGKey(self.target, file, "S-1-5-18")

    def find_key(self, name: str, sid: str | None = None) -> CNGKey | None:
        """Find a given CNG key based on the given GUID or comment value. Can also filter by SID."""
        for key in self.all_keys:
            if sid and key.sid != sid:
                continue
            if key.name == name:
                return key
        return None

    @export(record=CNGKeyRecord)
    def keys(self) -> Iterator[CNGKeyRecord]:
        """Yield CNG key records."""
        for key in self.all_keys:
            yield CNGKeyRecord(
                ts=key.path.lstat().st_mtime,
                name=key.name,
                source=key.path,
                _target=self.target,
            )
