import io
from pathlib import Path
from typing import BinaryIO, Union

from dissect.hypervisor import vdi

from dissect.target.container import Container


class VdiContainer(Container):
    """VirtualBox hard disks"""

    def __init__(self, fh: Union[BinaryIO, Path], *args, **kwargs):
        f = fh
        if not hasattr(fh, "read"):
            f = fh.open("rb")
        self.vdi = vdi.VDI(f)

        super().__init__(fh, self.vdi.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh: BinaryIO, original: Union[list, BinaryIO]) -> bool:
        magic = fh.read(68)
        fh.seek(-68, io.SEEK_CUR)
        return magic[-4:] == b"\x7f\x10\xda\xbe"

    @staticmethod
    def detect_path(path: Path, original: Union[list, BinaryIO]) -> bool:
        return path.suffix.lower() == ".vdi"

    def read(self, length: int) -> bytes:
        return self.vdi.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.vdi.seek(offset, whence)

    def tell(self) -> int:
        return self.vdi.tell()

    def close(self) -> None:
        pass
