from __future__ import annotations

from typing import BinaryIO

from dissect.hypervisor.util import vmtar

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import open_decompress


class VmtarFilesystem(TarFilesystem):
    __type__ = "vmtar"

    def __init__(self, fh: BinaryIO, base: str | None = None, *args, **kwargs):
        """Load a vmtar file (modified tar version used on ESXi).
        
        In most case vmtar files are compressed using zstd, xz or LZMA, and then using gzip.

        Args:
            fh: File-like object of a vmtar file.
            base: Base path in the tar file to open the filesystem on.
        """
        fh = open_decompress(fileobj=open_decompress(fileobj=fh))
        super().__init__(fh, base, *args, tarinfo=vmtar.VisorTarInfo, **kwargs)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a vmtar file on a given file-like object."""
        # vmtar files can be double compressed (gzip + lzma)
        fh = open_decompress(fileobj=open_decompress(fileobj=fh))

        fh.seek(257)
        return fh.read(8) == b"visor  \x00"
