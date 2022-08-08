import logging
import pathlib
from typing import BinaryIO, Iterator, Union

from dissect.fve import bde
from dissect.util.stream import AlignedStream

from dissect.target.exceptions import VolumeSystemError
from dissect.target.helpers.keychain import KeyType
from dissect.target.volume import EncryptedVolumeSystem, Volume

log = logging.getLogger(__name__)


class BitlockerVolumeSystemError(VolumeSystemError):
    pass


class BitlockerVolumeSystem(EncryptedVolumeSystem):

    PROVIDER = "bitlocker"

    def __init__(self, fh: Union[BinaryIO, list[BinaryIO]], *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.bde = bde.BDE(fh)

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        try:
            return bde.is_bde_volume(fh)
        except Exception:
            return False

    def _volumes(self) -> Iterator[Volume]:
        if isinstance(self.fh, Volume):
            volume_details = dict(
                number=self.fh.number,
                offset=self.fh.offset,
                vtype=self.fh.type,
                name=self.fh.name,
            )
        else:
            volume_details = dict(
                number=None,
                offset=0,
                vtype=None,
                name=None,
            )

        stream = self.unlock_volume()
        yield Volume(
            fh=stream,
            size=stream.size,
            raw=self.fh,
            vs=self,
            **volume_details,
        )

    def unlock_with_passphrase(self, passphrase: str) -> None:
        try:
            self.bde.unlock_with_passphrase(passphrase)
            log.debug("Unlocked BDE volume with provided passphrase")
        except ValueError:
            log.exception("Failed to unlock BDE volume with provided passphrase")

    def unlock_with_recovery_key(self, recovery_key: str) -> None:
        try:
            self.bde.unlock_with_recovery_password(recovery_key)
            log.debug("Unlocked BDE volume with recovery key")
        except ValueError:
            log.exception("Failed to unlock BDE volume with recovery password")

    def unlock_with_bek_file(self, bek_file: pathlib.Path) -> None:
        if not bek_file.exists():
            log.error("Provided BEK file does not exist: %s", bek_file)
            return

        with bek_file.open(mode="rb") as fh:
            try:
                self.bde.unlock_with_bek(fh)
                log.debug("Unlocked BDE volume with BEK file %s", bek_file)
            except ValueError:
                log.exception("Failed to unlock BDE volume with BEK file %s", bek_file)

    def unlock_volume(self) -> AlignedStream:
        if self.bde.has_clear_key():
            self.bde.unlock_with_clear_key()
        else:
            identifiers = [str(i) for i in self.bde.identifiers]
            keys = self.get_keys_for_identifiers(identifiers) + self.get_keys_without_identifier()

            for key in keys:
                if key.key_type == KeyType.PASSPHRASE and self.bde.has_passphrase():
                    self.unlock_with_passphrase(key.value)
                elif key.key_type == KeyType.RECOVERY_KEY and self.bde.has_recovery_password():
                    self.unlock_with_recovery_key(key.value)
                elif key.key_type == KeyType.FILE:
                    bek_file = pathlib.Path(key.value)
                    self.unlock_with_bek_file(bek_file)

                if self.bde.unlocked:
                    log.info("Volume %s with identifiers %s unlocked with %s", self.fh, identifiers, key)
                    break

        if self.bde.unlocked:
            return self.bde.open()
        else:
            raise BitlockerVolumeSystemError("Failed to unlock BDE volume")
