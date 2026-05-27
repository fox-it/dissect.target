from __future__ import annotations

import io
import re
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import BufferedStream

from dissect.target.container import Container
from dissect.target.helpers.logging import get_logger
from dissect.target.helpers.windows_ffi import _windows_get_disk_size, _windows_get_drive_size, run_on_windows

log = get_logger(__name__)


if TYPE_CHECKING:
    from pathlib import Path


def is_physical_drive_path(path: str) -> bool:
    r"""Check if path match a logical drive path, E.g : \\.\PhysicalDrive1 ."""
    return re.fullmatch(r"\\\\.\\+PhysicalDrive[0-9]+", path, re.IGNORECASE) is not None


def is_logical_drive_path(path: str) -> bool:
    r"""Check if path match a logical drive path, E.g : `\\.\C:` or `\\.\\\Z:` ."""
    return re.fullmatch(r"\\\\.\\+[a-z]:", path, re.IGNORECASE) is not None


def open_fh_on_drive(fh: Path) -> io.BufferedReader:
    """Open fh in rb mode. Allows to mock in test."""
    return fh.open("rb")


class WindowsDrive(Container):
    r"""Allows to load windows drive, such as `\\.\C:` or `\\.\PhysicalDrive1` directly from Windows.
    This Container is needed as Windows Drive does not support seek end, and must be wrapped inside a bufferedStream.
    Specific Windows api call must be used to retrieves drive length.
    """

    __type__ = "windows_drive"

    def __init__(self, fh: BinaryIO | Path, *args, **kwargs):
        if hasattr(fh, "read"):
            raise TypeError("Windows Drive can only be opened by path")
        if not run_on_windows():
            raise TypeError("Windows Drive is only available on Windows platform.")
        if is_physical_drive_path(path=str(fh)):
            drive_size = _windows_get_disk_size(str(fh))
        else:
            drive_size = _windows_get_drive_size(str(fh))
        self._raw_stream = open_fh_on_drive(fh)
        self.stream = BufferedStream(
            self._raw_stream,
            size=drive_size,
        )
        super().__init__(fh, drive_size, *args, **kwargs)

    @staticmethod
    def _detect_fh(fh: BinaryIO, original: list | BinaryIO) -> bool:
        return False

    @staticmethod
    def detect_path(path: Path, original: list | BinaryIO) -> bool:
        if not run_on_windows():
            return False
        # return path.drive == "\\\\.\\"
        return is_physical_drive_path(str(path)) or is_logical_drive_path(str(path))

    def read(self, length: int = -1) -> bytes:
        return self.stream.read(length)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.stream.seek(offset, whence)

    def tell(self) -> int:
        return self.stream.tell()

    def close(self) -> None:
        self.stream.close()
        self._raw_stream.close()
