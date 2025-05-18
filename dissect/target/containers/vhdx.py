from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.hypervisor import vhdx

from dissect.target.container import Container

if TYPE_CHECKING:
    from pathlib import Path


class VhdxContainer(Container):
    __type__ = "vhdx"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        self.vhdx = vhdx.VHDX(fh)
        super().__init__(fh, self.vhdx.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return fh.read(8) == b"vhdxfile"

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return path.suffix.lower() in (".vhdx", ".avhdx")

    def read(self, length: int) -> bytes:
        return self.vhdx.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.vhdx.seek(offset, whence)

    def tell(self) -> int:
        return self.vhdx.tell()

    def close(self) -> None:
        pass
