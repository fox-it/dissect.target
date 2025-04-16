from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.hypervisor.disk import c_qcow2, qcow2

from dissect.target.container import Container

if TYPE_CHECKING:
    from pathlib import Path


class QCow2Container(Container):
    __type__ = "qcow2"

    def __init__(
        self,
        fh: BinaryIO | Path,
        data_file: BinaryIO | None = None,
        backing_file: BinaryIO | int | None = None,
        *args,
        **kwargs,
    ):
        f = fh
        if not hasattr(fh, "read"):
            f = fh.open("rb")
        self.qcow2 = qcow2.QCow2(f, data_file, backing_file)

        super().__init__(fh, self.qcow2.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return fh.read(4) == c_qcow2.QCOW2_MAGIC_BYTES

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return path.suffix.lower() == ".qcow2"

    def read(self, length: int) -> bytes:
        return self.qcow2.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.qcow2.seek(offset, whence)

    def tell(self) -> int:
        return self.qcow2.tell()

    def close(self) -> None:
        pass
