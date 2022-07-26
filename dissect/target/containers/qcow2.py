import io
from pathlib import Path
from typing import BinaryIO, Union

from dissect.hypervisor.disk import qcow2, c_qcow2

from dissect.target.container import Container


class QCow2Container(Container):
    def __init__(self, fh: Union[BinaryIO, Path], data_file=None, backing_file=None, *args, **kwargs):
        f = fh
        if not hasattr(fh, "read"):
            f = fh.open("rb")
        self.qcow2 = qcow2.QCow2(f, data_file, backing_file)

        super().__init__(fh, self.qcow2.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh: BinaryIO, original: Union[list, BinaryIO]) -> bool:
        magic = fh.read(4)
        fh.seek(-4, io.SEEK_CUR)

        return magic == c_qcow2.QCOW2_MAGIC_BYTES

    @staticmethod
    def detect_path(path: Path, original: Union[list, BinaryIO]) -> bool:
        return path.suffix.lower() == ".qcow2"

    def read(self, length: int) -> bytes:
        return self.qcow2.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.qcow2.seek(offset, whence)

    def tell(self) -> int:
        return self.qcow2.tell()

    def close(self) -> None:
        pass
