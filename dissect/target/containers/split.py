import bisect
import io

from dissect.target.container import Container


class SplitContainer(Container):
    def __init__(self, fh, *args, **kwargs):
        self._fhs = []
        self.offsets = [0]
        offset = 0

        for f in fh:
            if not hasattr(f, "read"):
                f = f.open("rb")

            f.seek(0, io.SEEK_END)

            offset += f.tell()
            self.offsets.append(offset)
            self._fhs.append(f)
        self._roffset = 0

        super().__init__(fh, offset, *args, **kwargs)

    @staticmethod
    def detect_fh(fh, original):
        return isinstance(original, list) and len(original) > 1

    @staticmethod
    def detect_path(path, original):
        return isinstance(original, list) and len(original) > 1

    def read(self, length):
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

    def _read_partial(self, length):
        idx = bisect.bisect_right(self.offsets, self._roffset + 1) - 1
        fh = self._fhs[idx]

        img_offset = self.offsets[idx]
        fh.seek(self._roffset - img_offset)

        return fh.read(length)

    def seek(self, offset, whence=io.SEEK_SET):
        if whence is io.SEEK_SET:
            self._roffset = offset
        elif whence is io.SEEK_CUR:
            self._roffset += offset
        elif whence is io.SEEK_END:
            self._roffset = self.size + offset

        self._roffset = min(self._roffset, self.size)

    def tell(self):
        return self._roffset

    def close(self):
        pass
