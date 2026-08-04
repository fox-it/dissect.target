from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.hypervisor.disk.dmg import DMG, ENCRCDSA_MAGIC, KOLY_MAGIC

from dissect.target.container import Container
from dissect.target.helpers import keychain

if TYPE_CHECKING:
    from pathlib import Path


class DmgContainer(Container):
    """Apple Universal Disk Image Format (UDIF/DMG) container."""

    __type__ = "dmg"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        fh = fh.open("rb") if not hasattr(fh, "read") else fh

        self.dmg = self._open(fh)
        self._stream = self.dmg.open()

        super().__init__(fh, self.dmg.size, *args, **kwargs)

    def _open(self, fh: BinaryIO) -> DMG:
        fh.seek(0)
        if fh.read(len(ENCRCDSA_MAGIC)) != ENCRCDSA_MAGIC:
            return DMG(fh)

        # Encrypted DMG
        keys = keychain.get_keys_for_provider(self.__type__) + keychain.get_keys_without_provider()
        passphrases = [key.value for key in keys if key.key_type == keychain.KeyType.PASSPHRASE]
        if not passphrases:
            raise ValueError("Failed to unlock encrypted DMG: no passphrase(s) provided")

        for passphrase in passphrases:
            try:
                return DMG(fh, password=passphrase)
            except ValueError:  # noqa: PERF203
                continue

        raise ValueError("Failed to unlock encrypted DMG using the provided passphrase(s)")

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        if fh.read(8) == ENCRCDSA_MAGIC:
            return True

        fh.seek(-512, io.SEEK_END)
        return fh.read(4) == KOLY_MAGIC

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        # A DMG can be either a raw disk image or a UDIF image. As both share the same extension, we cannot detect
        # based on the path alone and instead rely on the magic detected by _detect_fh.
        return False

    def read(self, length: int) -> bytes:
        return self._stream.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._stream.seek(offset, whence)

    def tell(self) -> int:
        return self._stream.tell()

    def close(self) -> None:
        if hasattr(self, "_stream") and not self._stream.closed:
            self._stream.close()

        if hasattr(self, "dmg"):
            self.dmg.close()
