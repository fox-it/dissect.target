import io
import re
from pathlib import Path
from typing import BinaryIO, Union

from dissect.evidence import EWF
from dissect.evidence.ewf import find_files

from dissect.target.container import Container


class EwfContainer(Container):
    """Expert Witness Disk Image Format"""

    def __init__(self, fh: Union[list, BinaryIO, Path], *args, **kwargs):
        fhs = [fh] if not isinstance(fh, list) else fh
        if hasattr(fhs[0], "read"):
            self.ewf = EWF(fhs)
        else:
            self.ewf = EWF([path.open("rb") for path in find_files(fhs[0])])

        super().__init__(fh, self.ewf.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh: BinaryIO, original: Union[list, BinaryIO]) -> bool:
        """Detect file header"""
        magic = fh.read(3)
        fh.seek(-3, io.SEEK_CUR)

        return magic == b"EVF" or magic == b"LVF" or magic == b"LEF"

    @staticmethod
    def detect_path(path: Path, original: Union[list, BinaryIO]) -> bool:
        """Detect path"""
        return re.match(r"\.[EeLs]x?01$", path.suffix)

    def read(self, length: int) -> bytes:
        return self.ewf.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.ewf.seek(offset, whence)

    def tell(self) -> int:
        return self.ewf.tell()

    def close(self) -> None:
        self.ewf.close()
