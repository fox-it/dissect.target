import io
from pathlib import Path
from typing import BinaryIO, Union

from dissect.target.container import Container, register


class TestContainer(Container):
    def __init__(self, fh: Union[BinaryIO, Path], vs=None):
        super().__init__(fh, size=20, vs=vs)

    def __repr__(self):
        return f"<{self.__class__.__name__} size={self.size} vs={self.vs}>"

    @staticmethod
    def detect_fh(fh: BinaryIO, original: Union[list, BinaryIO]) -> bool:
        return False

    @staticmethod
    def detect_path(path: Path, original: Union[list, Path]) -> bool:
        return False

    def read(self, length: int) -> bytes:
        return self.fh.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.fh.seek(offset, whence)

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.fh.tell()

    def close(self) -> None:
        pass


register(__name__, TestContainer.__name__, internal=False)
