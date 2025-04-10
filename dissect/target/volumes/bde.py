from __future__ import annotations

import logging
import pathlib
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve import bde

from dissect.target.exceptions import VolumeSystemError
from dissect.target.helpers.keychain import KeyType
from dissect.target.volume import EncryptedVolumeSystem, Volume

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.util.stream import AlignedStream

log = logging.getLogger(__name__)


class BitlockerVolumeSystemError(VolumeSystemError):
    pass


class BitlockerVolumeSystem(EncryptedVolumeSystem):
    __type__ = "bitlocker"

    def __init__(self, fh: BinaryIO | list[BinaryIO], *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.bde = bde.BDE(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return bde.is_bde_volume(fh)

    def _volumes(self) -> Iterator[Volume]:
        if isinstance(self.fh, Volume):
            volume_details = {
                "number": self.fh.number,
                "offset": self.fh.offset,
                "vtype": self.fh.type,
                "name": self.fh.name,
                "guid": self.fh.guid,
            }
        else:
            volume_details = {
                "number": 1,
                "offset": 0,
                "vtype": None,
                "name": None,
            }

        stream = self.unlock_volume()
        yield Volume(
            fh=stream,
            size=stream.size,
            raw=self.fh,
            disk=self.disk,
            vs=self,
            **volume_details,
        )

    def unlock_with_passphrase(self, passphrase: str, is_wildcard: bool = False) -> None:
        try:
            self.bde.unlock_with_passphrase(passphrase)
            log.debug("Unlocked BDE volume with provided passphrase")
        except ValueError:
            if not is_wildcard:
                log.exception("Failed to unlock BDE volume with provided passphrase")

    def unlock_with_recovery_key(self, recovery_key: str, is_wildcard: bool = False) -> None:
        try:
            self.bde.unlock_with_recovery_password(recovery_key)
            log.debug("Unlocked BDE volume with recovery key")
        except ValueError:
            if not is_wildcard:
                log.exception("Failed to unlock BDE volume with recovery password")

    def unlock_with_bek_file(self, bek_file: pathlib.Path, is_wildcard: bool = False) -> None:
        if not bek_file.exists():
            if not is_wildcard:
                log.error("Provided BEK file does not exist: %s", bek_file)
            return

        with bek_file.open(mode="rb") as fh:
            try:
                self.bde.unlock_with_bek(fh)
                log.debug("Unlocked BDE volume with BEK file %s", bek_file)
            except ValueError:
                if not is_wildcard:
                    log.exception("Failed to unlock BDE volume with BEK file %s", bek_file)

    def unlock_with_fvek(self, raw_key: bytes, is_wildcard: bool = False) -> None:
        try:
            self.bde.unlock_with_fvek(raw_key)
        except ValueError:
            if not is_wildcard:
                log.exception("Failed to unlock BDE volume with raw FVEK key (%r)", raw_key)

    def unlock_volume(self) -> AlignedStream:
        if self.bde.has_clear_key():
            self.bde.unlock_with_clear_key()
        else:
            identifiers = [str(i) for i in self.bde.identifiers]
            keys = self.get_keys_for_identifiers(identifiers) + self.get_keys_without_identifier()

            for key in keys:
                if key.key_type == KeyType.PASSPHRASE and self.bde.has_passphrase():
                    self.unlock_with_passphrase(key.value, key.is_wildcard)
                elif key.key_type == KeyType.RECOVERY_KEY and self.bde.has_recovery_password():
                    self.unlock_with_recovery_key(key.value, key.is_wildcard)
                elif key.key_type == KeyType.FILE:
                    bek_file = pathlib.Path(key.value)
                    self.unlock_with_bek_file(bek_file, key.is_wildcard)
                elif key.key_type == KeyType.RAW:
                    self.unlock_with_fvek(key.value, key.is_wildcard)

                if self.bde.unlocked:
                    log.info("Volume %s with identifiers %s unlocked with %s", self.fh, identifiers, key)
                    break

        if self.bde.unlocked:
            return self.bde.open()
        raise BitlockerVolumeSystemError("Failed to unlock BDE volume")
