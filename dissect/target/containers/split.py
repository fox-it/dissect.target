import bisect
import io
from pathlib import Path
from typing import BinaryIO, List, Union

from dissect.target.container import Container


def find_files(path: Path) -> List[Path]:
    path = path.resolve()
    return sorted([f for f in path.parent.glob(path.stem + ".*") if f.suffix[1:].isdigit()])


class SplitContainer(Container):
    def __init__(self, fh: Union[list, BinaryIO, Path], *args, **kwargs):
        self._fhs = []
        self.offsets = [0]
        offset = 0

        fhs = [fh] if not isinstance(fh, list) else fh
        if isinstance(fhs[0], Path):
            fhs = [path.open("rb") for path in find_files(fhs[0])]

        for f in fhs:
            f.seek(0, io.SEEK_END)

            offset += f.tell()
            self.offsets.append(offset)
            self._fhs.append(f)
        self._roffset = 0

        super().__init__(fh, offset, *args, **kwargs)

    @staticmethod
    def detect_fh(fh: BinaryIO, original: Union[list, BinaryIO]) -> bool:
        return isinstance(original, list) and len(original) > 1

    @staticmethod
    def detect_path(path: Path, original: Union[list, BinaryIO]) -> bool:
        return (path.suffix[1:].isdigit() and len(find_files(path)) > 1) or (
            isinstance(original, list) and len(original) > 1
        )

    def read(self, length: int) -> bytes:
        length = min(length, self.size - self._roffset)
        buf = b""

        while length > 0:
            data = self._read_partial(length)
            if not data:
                break

            length -= len(data)
            buf += data
            self._roffset += len(data)

        return buf

    def _read_partial(self, length: int) -> bytes:
        idx = bisect.bisect_right(self.offsets, self._roffset + 1) - 1
        fh = self._fhs[idx]

        img_offset = self.offsets[idx]
        fh.seek(self._roffset - img_offset)

        return fh.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence is io.SEEK_SET:
            self._roffset = offset
        elif whence is io.SEEK_CUR:
            self._roffset += offset
        elif whence is io.SEEK_END:
            self._roffset = self.size + offset

        self._roffset = min(self._roffset, self.size)
        return self._roffset

    def tell(self) -> int:
        return self._roffset

    def close(self) -> None:
        pass
