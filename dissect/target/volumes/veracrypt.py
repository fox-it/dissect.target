from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.veracrypt import VeraCrypt, is_veracrypt_volume

from dissect.target.exceptions import VolumeSystemError
from dissect.target.helpers import keychain
from dissect.target.helpers.keychain import KeyType
from dissect.target.volume import EncryptedVolumeSystem, Volume

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.util.stream import AlignedStream


log = logging.getLogger(__name__)


class VeraCryptVolumeSystemError(VolumeSystemError):
    pass


class VeraCryptVolumeSystem(EncryptedVolumeSystem):
    """VeraCrypt encrypted system volume implementation.

    References:
        - https://veracrypt.jp
        - https://github.com/veracrypt/VeraCrypt
    """

    __type__ = "veracrypt"

    def __init__(self, fh: BinaryIO | Volume, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)

        if is_system := is_system_volume(fh):
            fh = fh.disk

        self.veracrypt = VeraCrypt(fh, is_system=is_system)

    @staticmethod
    def _detect(fh: BinaryIO | Volume) -> bool:
        """Detect by checking for certain VeraCrypt volume characteristics and if any keychain value(s) are given."""
        # NOTE: For VeraCrypt encrypted system volumes, the Windows EFI partition will include VeraCrypt files.
        # However, from this context we do not have access to that filesystem, so we have to be a little more creative.
        keys = keychain.get_keys_for_provider("veracrypt") + keychain.get_keys_without_provider()
        return any(keys) and is_veracrypt_volume(fh)

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

    def unlock_with_passphrase(self, passphrase: str, is_wildcard: bool = False) -> None:
        try:
            self.veracrypt.unlock_with_passphrase(passphrase)
            log.debug("Unlocked VeraCrypt volume with provided passphrase %r", passphrase)

        except ValueError:
            if not is_wildcard:
                log.exception("Failed to unlock VeraCrypt volume with provided passphrase")

    def unlock_with_header_key(self, key: bytes, is_wildcard: bool = False) -> None:
        try:
            self.veracrypt.unlock_with_header_key(key)
            log.debug("Unlocked VeraCrypt volume with provided header key %r", key)

        except ValueError:
            if not is_wildcard:
                log.exception("Failed to unlock VeraCrypt volume with provided header key")

    def unlock_with_key_file(self, key: Path, is_wildcard: bool = False) -> None:
        if not is_wildcard:
            log.warning("VeraCrypt implementation does not yet support keyfiles")

    def unlock_volume(self) -> AlignedStream:
        """Attempt to unlock the volume using keychain keys."""
        for key in self.keys:
            if key.key_type == KeyType.RAW:
                self.unlock_with_header_key(key.value, key.is_wildcard)
            if key.key_type == KeyType.PASSPHRASE:
                self.unlock_with_passphrase(key.value, key.is_wildcard)
            if key.key_type == KeyType.FILE:
                self.unlock_with_key_file(Path(key.value), key.is_wildcard)

            if self.veracrypt.unlocked:
                log.info("Volume %s unlocked with %s", self.fh, key)
                break

        if self.veracrypt.unlocked:
            return self.veracrypt.open()

        raise VeraCryptVolumeSystemError("Failed to unlock VeraCrypt volume")


def is_system_volume(fh: BinaryIO | Volume) -> bool:
    """Using some heuristics we attempt to detect if this file handle is an encrypted *system* volume or not.

    This will might produce unexpected results for custom partitioning schemes.

    By default a Windows GPT disk will have the following volumes:
        - EFI partition (100 MB >)
        - Reserved partition (MSR) (16 MB)
        - Sysvol partition
        - Recovery partition (WinRE) (750 MB >)

    A Windows MBR disk will have the following volumes:
        - Boot partition (100 MB)
        - System partition
        - Recovery partition (WinRE) (750 MB >)

    We check if the preceding volumes look like a reserved partition and an EFI partition. If so, this is
    likely the system volume.

    For performance reasons we do not attempt to load the uninitialized filesystems of these partitions.
    A future version could check if the last partition of the disk is the WinRE partition, as that seems
    to be a requirement for recent Windows versions.
    """
    if not isinstance(fh, Volume) or not fh.vs:
        return False

    index = fh.vs.volumes.index(fh)

    # If there is not at least one preceding volume on this disk (EFI or EFI and MSR),
    # this is likely not a system partition.
    if index < 1 or len(fh.vs.volumes) < 3:
        return False

    # The preceding volume can either be the MSR (on GPT disks) or boot partition (on MBR disks).
    preceding_volume = fh.vs.volumes[index - 1]
    approx_16mb = range(15 * 1024 * 1024, 17 * 1024 * 1024)
    approx_100mb = range(99 * 1024 * 1024, 101 * 1024 * 1024)

    return (preceding_volume.name == "Microsoft reserved partition" and preceding_volume.size in approx_16mb) or (
        preceding_volume.name == "Basic data partition" and preceding_volume.size in approx_100mb
    )
