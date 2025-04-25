from __future__ import annotations

import io
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence import AsdfSnapshot, AsdfStream
from dissect.evidence.asdf import FILE_MAGIC

from dissect.target.container import Container

if TYPE_CHECKING:
    from pathlib import Path


class AsdfContainer(Container):
    __type__ = "asdf"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        file_container = fh

        if not hasattr(file_container, "read"):
            file_container = AsdfSnapshot(fh.open("rb"))

        if isinstance(file_container, AsdfSnapshot):
            file_container = fh.open(0)

        if not isinstance(file_container, AsdfStream):
            raise TypeError(f"Invalid type for AsdfContainer: {fh}")

        self.asdf = file_container

        super().__init__(fh, self.asdf.size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return fh.read(4) == FILE_MAGIC

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        return path.suffix.lower() == ".asdf"

    def read(self, length: int) -> bytes:
        return self.asdf.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.asdf.seek(offset, whence)

    def tell(self) -> int:
        return self.asdf.tell()

    def close(self) -> None:
        self.asdf.close()
