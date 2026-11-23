from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.hypervisor import vdi

from dissect.target.container import Container

if TYPE_CHECKING:
    from pathlib import Path


class VdiContainer(Container):
    """VirtualBox hard disks."""

    __type__ = "vdi"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        self.vdi = vdi.VDI(fh)

        self._stream = self.vdi.open()
        super().__init__(fh, self.vdi.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return fh.read(68)[-4:] == b"\x7f\x10\xda\xbe"

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return path.suffix.lower() == ".vdi"

    def read(self, length: int) -> bytes:
        return self._stream.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._stream.seek(offset, whence)

    def tell(self) -> int:
        return self._stream.tell()

    def close(self) -> None:
        self._stream.close()
        self.vdi.close()
