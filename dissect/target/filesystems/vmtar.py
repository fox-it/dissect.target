from typing import BinaryIO, Optional

from dissect.hypervisor.util import vmtar

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import open_decompress


class VmtarFilesystem(TarFilesystem):
    __type__ = "vmtar"

    def __init__(self, fh: BinaryIO, base: Optional[str] = None, *args, **kwargs):
        fh = open_decompress(fileobj=open_decompress(fileobj=fh))
        super().__init__(fh, base, tarinfo=vmtar.VisorTarInfo, *args, **kwargs)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a vmtar file on a given file-like object."""
        # vmtar files can be double compressed (gzip + lzma)
        fh = open_decompress(fileobj=open_decompress(fileobj=fh))

        fh.seek(257)
        return fh.read(8) == b"visor  \x00"
