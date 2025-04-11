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
        f = fh
        if not hasattr(fh, "read"):
            f = fh.open("rb")
        self.vdi = vdi.VDI(f)

        super().__init__(fh, self.vdi.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return fh.read(68)[-4:] == b"\x7f\x10\xda\xbe"

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return path.suffix.lower() == ".vdi"

    def read(self, length: int) -> bytes:
        return self.vdi.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.vdi.seek(offset, whence)

    def tell(self) -> int:
        return self.vdi.tell()

    def close(self) -> None:
        pass
