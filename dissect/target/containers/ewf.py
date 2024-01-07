import io
import re
from pathlib import Path
from typing import BinaryIO, Union

from dissect.evidence import EWF
from dissect.evidence.ewf import find_files

from dissect.target.container import Container


class EwfContainer(Container):
    """Expert Witness Disk Image Format"""

    __type__ = "ewf"

    def __init__(self, fh: Union[list, BinaryIO, Path], *args, **kwargs):
        fhs = [fh] if not isinstance(fh, list) else fh
        if hasattr(fhs[0], "read"):
            self.ewf = EWF(fhs)
        else:
            self.ewf = EWF([path.open("rb") for path in find_files(fhs[0])])

        self._stream = self.ewf.open()
        super().__init__(fh, self.ewf.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: Union[list, BinaryIO]) -> bool:
        """Detect file header"""
        return fh.read(3) in (b"EVF", b"LVF", b"LEF")

    @staticmethod
    def detect_path(path: Path, original: Union[list, BinaryIO]) -> bool:
        """Detect path"""
        return re.match(r"\.[EeLs]x?01$", path.suffix)

    def read(self, length: int) -> bytes:
        return self._stream.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self._stream.seek(offset, whence)

    def tell(self) -> int:
        return self._stream.tell()

    def close(self) -> None:
        self._stream.close()
