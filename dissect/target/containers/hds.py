from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.hypervisor.disk import hdd
from dissect.hypervisor.disk.c_hdd import c_hdd

from dissect.target.container import Container

if TYPE_CHECKING:
    from pathlib import Path


class HdsContainer(Container):
    __type__ = "hds"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        f = fh
        if not hasattr(fh, "read"):
            f = fh.open("rb")

        self.hds = hdd.HDS(f)
        super().__init__(fh, self.hds.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return fh.read(16) in (c_hdd.SIGNATURE_STRUCTURED_DISK_V1, c_hdd.SIGNATURE_STRUCTURED_DISK_V2)

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return path.suffix.lower() == ".hds"

    def read(self, length: int) -> bytes:
        return self.hds.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.hds.seek(offset, whence)

    def tell(self) -> int:
        return self.hds.tell()

    def close(self) -> None:
        self.hds.close()
