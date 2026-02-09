from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.hypervisor import hdd

from dissect.target.container import Container

if TYPE_CHECKING:
    from pathlib import Path


class HddContainer(Container):
    __type__ = "hdd"

    def __init__(self, fh: Path, *args, **kwargs):
        if hasattr(fh, "read"):
            raise TypeError("HddContainer can only be opened by path")

        self.hdd = hdd.HDD(fh)
        self.stream = self.hdd.open()
        super().__init__(fh, self.stream.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return False

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return path.suffix.lower() == ".hdd"

    def read(self, length: int) -> bytes:
        return self.stream.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.stream.seek(offset, whence)

    def tell(self) -> int:
        return self.stream.tell()

    def close(self) -> None:
        self.stream.close()
