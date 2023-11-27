import io
from pathlib import Path
from typing import BinaryIO, Union

from dissect.hypervisor import vhd

from dissect.target.container import Container


class VhdContainer(Container):
    __type__ = "vhd"

    def __init__(self, fh: Union[BinaryIO, Path], *args, **kwargs):
        f = fh
        if not hasattr(fh, "read"):
            f = fh.open("rb")
        self.vhd = vhd.VHD(f)

        super().__init__(fh, self.vhd.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: Union[list, BinaryIO]) -> bool:
        fh.seek(-512, io.SEEK_END)
        return b"conectix" in fh.read(9)

    @staticmethod
    def detect_path(path: Path, original: Union[list, BinaryIO]) -> bool:
        return path.suffix.lower() == ".vhd"

    def read(self, length: int) -> bytes:
        return self.vhd.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.vhd.seek(offset, whence)

    def tell(self) -> int:
        return self.vhd.tell()

    def close(self) -> None:
        pass
