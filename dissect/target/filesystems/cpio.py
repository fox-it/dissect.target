from typing import BinaryIO, Optional

from dissect.util import cpio

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import open_decompress


class CpioFilesystem(TarFilesystem):
    __type__ = "cpio"

    def __init__(self, fh: BinaryIO, base: Optional[str] = None, *args, **kwargs):
        super().__init__(open_decompress(fileobj=fh), base, tarinfo=cpio.CpioInfo, *args, **kwargs)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a cpio file on a given file-like object."""
        return cpio.detect_header(open_decompress(fileobj=fh)) != cpio.FORMAT_CPIO_UNKNOWN
