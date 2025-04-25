from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream, BufferedStream

from dissect.target.container import Container

if TYPE_CHECKING:
    from pathlib import Path


class RawContainer(Container):
    __type__ = "raw"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        if not hasattr(fh, "read"):
            fh = fh.open("rb")

        if not hasattr(fh, "size"):
            fh.seek(0, io.SEEK_END)
            size = fh.tell()
            fh.seek(0)
        elif callable(fh.size):
            size = fh.size()
        else:
            size = fh.size

        if not isinstance(fh, AlignedStream):
            fh = BufferedStream(fh, size=size)

        self.read = fh.read
        self.seek = fh.seek
        self.tell = fh.tell
        self.close = fh.close

        super().__init__(fh, size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return True

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return True
