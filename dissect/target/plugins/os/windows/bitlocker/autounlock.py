from __future__ import annotations

from itertools import chain
from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.dpapi.blob import DPAPI_BLOB_MAGIC

if TYPE_CHECKING:
    from collections.abc import Iterator

auto_unlock_def = """
struct Element {
    DWORD       size;
    DWORD       unknown1;
    DWORD       unknown2;
    DWORD       unknown3;
    CHAR        key[EOF];
};

struct Info {
    DWORD       size;
    DWORD       unknown1;
    WORD        unknown2;
    WORD        unknown3;
    DWORD       unknown4;
    DWORD       unknown5;
    CHAR        padding1[4 * 3];
    QWORD       timestamp;
    CHAR        guid[16];
    QWORD       unknown7;
    DWORD       unknown8;
    CHAR        padding2[4 * 3];
    Element     element;
};
"""
c_auto_unlock = cstruct().load(auto_unlock_def)

AutoUnlockRecord = TargetRecordDescriptor(
    "windows/bitlocker/auto_unlock",
    [
        ("datetime", "ts"),
        ("string", "guid"),
        ("string", "key"),
        ("path", "source"),
    ],
)


class BitlockerAutoUnlock(Plugin):
    """Microsoft Windows Bitlocker FVE auto unlock plugin."""

    __namespace__ = "bitlocker"

    SYSTEM_PATH = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\FVEAutoUnlock"
    USER_PATH = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\FveAutoUnlock"

    def check_compatible(self) -> None:
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("No Windows registry present")

        if not any(chain(self.target.registry.keys(self.USER_PATH), self.target.registry.keys(self.SYSTEM_PATH))):
            raise UnsupportedPluginError("No FveAutoUnlock registry values found")

    @export(record=AutoUnlockRecord)
    def auto_unlock(self) -> Iterator[AutoUnlockRecord]:
        """Search for FVE auto unlock keys."""
        for key in chain(self.target.registry.keys(self.USER_PATH), self.target.registry.keys(self.SYSTEM_PATH)):
            for subkey in key.subkeys():
                guid = subkey.name.strip(r"{}")

                try:
                    info_enc = subkey.value("info").value
                except RegistryError as e:
                    self.target.log.warning("Unexpected error when querying registry key %s (%s): %s", key, subkey, e)
                    continue

                if info_enc.startswith(DPAPI_BLOB_MAGIC):
                    try:
                        info = self.target.dpapi.decrypt_blob(info_enc)
                    except ValueError as e:
                        self.target.log.warning(
                            "Unable to decrypt BitLocker auto unlock DPAPI blob at %s: %s", subkey, e
                        )
                        continue
                else:
                    info = info_enc

                # We do not parse the 'element' key value as the 'info' contains more information.
                try:
                    info_struct = c_auto_unlock.Info(info)
                    bde_key = info_struct.element.key.hex()
                except Exception as e:
                    self.target.log.warning("Unable to parse FveAutoUnlock 'info' element: %s", e)
                    self.target.log.debug("", exc_info=e)
                    continue

                yield AutoUnlockRecord(
                    ts=wintimestamp(info_struct.timestamp),
                    guid=guid,
                    key=bde_key,
                    source=str(key.hive.filepath) + "\\" + self.USER_PATH + "\\" + subkey.name,
                    _target=self.target,
                )
