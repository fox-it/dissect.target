import io
import re

from dissect.evidence import EWF
from dissect.evidence.ewf import find_files
from dissect.target.container import Container


class EwfContainer(Container):
    """Expert Witness Disk Image Format"""

    def __init__(self, fh, *args, **kwargs):
        fhs = [fh] if not isinstance(fh, list) else fh
        if hasattr(fhs[0], "read"):
            self.ewf = EWF(fhs)
        else:
            self.ewf = EWF([path.open("rb") for path in find_files(fhs[0])])

        super().__init__(fh, self.ewf.size, *args, **kwargs)

    @staticmethod
    def detect_fh(fh, original):
        """Detect file header"""
        magic = fh.read(3)
        fh.seek(-3, io.SEEK_CUR)

        return magic == b"EVF" or magic == b"LVF" or magic == b"LEF"

    @staticmethod
    def detect_path(path, original):
        """Detect path"""
        return re.match(r"\.[EeLs]x?01$", path.suffix)

    def read(self, length):
        return self.ewf.read(length)

    def seek(self, offset, whence=io.SEEK_SET):
        self.ewf.seek(offset, whence)

    def tell(self):
        return self.ewf.tell()

    def close(self):
        self.ewf.close()
