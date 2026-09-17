from __future__ import annotations

from itertools import chain
from typing import TYPE_CHECKING

from dissect.cstruct import cstruct
from dissect.fve.bde.c_bde import FVE_DATUM_ROLE, FVE_DATUM_TYPE
from dissect.fve.bde.information import Datum
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.dpapi.blob import DPAPI_BLOB_MAGIC

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.fve.bde import BDE

    from dissect.target.target import Target

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
        ("string", "volume_type"),
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
        """Search for FVE auto unlock keys belonging to fixed or removable BitLocker volumes."""
        # Iterate HKCU keys for removable data drive key material (BitLocker To Go)
        for key in self.target.registry.keys(self.USER_PATH):
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
                    volume_type="removable",
                    guid=guid,
                    key=bde_key,
                    source=str(key.hive.filepath) + "\\" + self.USER_PATH + "\\" + subkey.name,
                    _target=self.target,
                )

        # Iterate HKCU for fixed data drives key material (depends on system volume BitLocker Datum)
        for key in self.target.registry.keys(self.SYSTEM_PATH):
            for subkey in key.subkeys():
                guid = subkey.name.strip(r"{}")

                try:
                    data = subkey.value("Data").value
                except RegistryError as e:
                    self.target.log.warning("Unexpected error when querying registry key %s (%s): %s", key, subkey, e)
                    continue

                external_info_datum = Datum.from_bytes(data)
                encrypted_datum = next(external_info_datum.find_property(FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY))

                try:
                    bde = find_sysvol_bde(self.target)
                except ValueError as e:
                    self.target.log.warning("Failed to find system volume BitLocker: %s", e)
                    self.target.log.debug("", exc_info=e)
                    continue

                try:
                    encrypted_auto_unlock_datum = next(
                        bde.information.dataset.find_datum(
                            role=FVE_DATUM_ROLE.AUTO_UNLOCK,
                            type_=FVE_DATUM_TYPE.AES_CCM_ENCRYPTED_KEY,
                        )
                    )
                except StopIteration:
                    self.target.log.warning("No AUTO_UNLOCK Datum found in sysvol BitLocker dataset")
                    continue

                try:
                    extern_key_datum = encrypted_auto_unlock_datum.unbox(bde._used_key)
                    key_datum = encrypted_datum.unbox(extern_key_datum)
                except ValueError as e:
                    self.target.log.warning("Failed to unbox key datums for %s: %s", guid, e)
                    self.target.log.debug("", exc_info=e)
                    continue

                yield AutoUnlockRecord(
                    ts=external_info_datum.datetime,
                    volume_type="fixed",
                    guid=external_info_datum.identifier,
                    key=key_datum.data.hex(),
                    source=str(key.hive.filepath) + "\\" + self.SYSTEM_PATH + "\\" + subkey.name,
                    _target=self.target,
                )


def find_sysvol_bde(target: Target) -> BDE | None:
    """Find the :class:`BDE` instance of the :class:`Target` system volume."""
    try:
        sysvol = target.fs.mounts["sysvol"]
        bde: BDE = sysvol.volume.vs.bde
    except KeyError as e:
        raise ValueError("Target has no sysvol") from e
    except AttributeError as e:
        raise ValueError("Sysvol is not BitLocker encrypted") from e

    return bde
