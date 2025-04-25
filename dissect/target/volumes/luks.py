from __future__ import annotations

import logging
import pathlib
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve import luks

from dissect.target.exceptions import VolumeSystemError
from dissect.target.helpers.keychain import KeyType
from dissect.target.volume import EncryptedVolumeSystem, Volume

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.util.stream import AlignedStream

log = logging.getLogger(__name__)


class LUKSVolumeSystemError(VolumeSystemError):
    pass


class LUKSVolumeSystem(EncryptedVolumeSystem):
    __type__ = "luks"

    def __init__(self, fh: BinaryIO | list[BinaryIO], *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.luks = luks.LUKS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return luks.is_luks_volume(fh)

    def _volumes(self) -> Iterator[Volume]:
        if isinstance(self.fh, Volume):
            volume_details = {
                "number": self.fh.number,
                "offset": self.fh.offset,
                "vtype": self.fh.type,
                "name": self.fh.name,
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

    def unlock_with_volume_encryption_key(
        self, key: bytes, keyslot: int | None = None, is_wildcard: bool = False
    ) -> None:
        try:
            if keyslot is None:
                for keyslot in self.luks.keyslots:
                    try:
                        self.luks.unlock(key, keyslot)
                        break
                    except ValueError:
                        continue
                else:
                    raise ValueError("Failed to find matching keyslot for provided volume encryption key")  # noqa: TRY301
            else:
                self.luks.unlock(key, keyslot)

            log.debug("Unlocked LUKS volume with provided volume encryption key")
        except ValueError:
            if not is_wildcard:
                log.exception("Failed to unlock LUKS volume with provided volume encryption key")

    def unlock_with_passphrase(self, passphrase: str, keyslot: int | None = None, is_wildcard: bool = False) -> None:
        try:
            self.luks.unlock_with_passphrase(passphrase, keyslot)
            log.debug("Unlocked LUKS volume with provided passphrase")
        except ValueError:
            if not is_wildcard:
                log.exception("Failed to unlock LUKS volume with provided passphrase")

    def unlock_with_key_file(
        self, key_file: pathlib.Path, keyslot: int | None = None, is_wildcard: bool = False
    ) -> None:
        if not key_file.exists():
            if not is_wildcard:
                log.error("Provided key file does not exist: %s", key_file)
            return

        try:
            self.luks.unlock_with_key_file(key_file, keyslot=keyslot)
            log.debug("Unlocked LUKS volume with key file %s", key_file)
        except ValueError:
            if not is_wildcard:
                log.exception("Failed to unlock LUKS volume with key file %s", key_file)

    def unlock_volume(self) -> AlignedStream:
        keyslots = list(map(str, self.luks.keyslots.keys()))
        keys = self.get_keys_for_identifiers(keyslots) + self.get_keys_without_identifier()

        for key in keys:
            try:
                keyslot = int(key.identifier)
            except Exception:
                keyslot = None

            if key.key_type == KeyType.RAW:
                self.unlock_with_volume_encryption_key(key.value, keyslot, key.is_wildcard)
            if key.key_type == KeyType.PASSPHRASE:
                self.unlock_with_passphrase(key.value, keyslot, key.is_wildcard)
            elif key.key_type == KeyType.FILE:
                key_file = pathlib.Path(key.value)
                self.unlock_with_key_file(key_file, keyslot, key.is_wildcard)

            if self.luks.unlocked:
                log.info("Volume %s unlocked with %s (keyslot: %d)", self.fh, key, self.luks._active_keyslot_id)
                break

        if self.luks.unlocked:
            return self.luks.open()
        raise LUKSVolumeSystemError("Failed to unlock LUKS volume")
