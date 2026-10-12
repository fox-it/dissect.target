from __future__ import annotations

import io
import re
from pathlib import Path
from typing import BinaryIO

from dissect.evidence import EWF

from dissect.target.container import Container
from dissect.target.helpers import keychain


class EwfContainer(Container):
    """Expert Witness Disk Image Format."""

    __type__ = "ewf"

    def __init__(self, fh: list | BinaryIO | Path, *args, **kwargs):
        self.ewf = EWF(fh)

        if self.ewf.is_adcrypt():
            keys = keychain.get_keys_for_provider(self.__type__) + keychain.get_keys_without_provider()

            if not keys:
                raise ValueError("Failed to unlock ADCRYPT: no key(s) provided")

            for key in keys:
                try:
                    if key.key_type == keychain.KeyType.PASSPHRASE:
                        self.ewf.unlock(passphrase=key.value)
                    elif key.key_type == keychain.KeyType.FILE and (path := Path(key.value)).is_file():
                        self.ewf.unlock(private_key=path)
                except ValueError:  # noqa: PERF203
                    pass

            if self.ewf.is_locked():
                raise ValueError("Failed to unlock ADCRYPT using provided key(s)")

        self._stream = self.ewf.open()
        super().__init__(fh, self.ewf.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return fh.read(3) in (b"EVF", b"LVF", b"LEF")

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return re.match(r"\.[EeLs]x?01$", path.suffix)

    def read(self, length: int) -> bytes:
        return self._stream.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._stream.seek(offset, whence)

    def tell(self) -> int:
        return self._stream.tell()

    def close(self) -> None:
        if hasattr(self, "_stream") and not self._stream.closed:
            self._stream.close()

        if hasattr(self, "ewf"):
            self.ewf.close()
