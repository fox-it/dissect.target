from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.hypervisor.disk import asif

from dissect.target.container import Container

if TYPE_CHECKING:
    from pathlib import Path


class AsifContainer(Container):
    __type__ = "asif"

    def __init__(
        self,
        fh: BinaryIO | Path,
        *args,
        **kwargs,
    ):
        self.asif = asif.ASIF(fh.open("rb") if not hasattr(fh, "read") else fh)
        self.stream = self.asif.open()

        super().__init__(fh, self.asif.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return fh.read(4) == b"shdw"

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return path.suffix.lower() == ".asif"

    def read(self, length: int) -> bytes:
        return self.stream.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.stream.seek(offset, whence)

    def tell(self) -> int:
        return self.stream.tell()

    def close(self) -> None:
        self.stream.close()
