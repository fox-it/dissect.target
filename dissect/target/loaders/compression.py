from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import fsutil
from dissect.target.helpers.logging import get_logger
from dissect.target.loader import MiddlewareLoader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import target

log = get_logger(__name__)

COMPRESSION_EXT = (".gz", ".lzma", ".bz2", ".zst")


class CompressionLoader(MiddlewareLoader):
    """
    Allow loading compressed files.
    This does impact performance, so it's recommended to uncompress the file before passing it to Dissect.
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)

        log.warning(
            "file %r is compressed, which will affect performance. "
            "Consider uncompressing the archive before passing the file to Dissect.",
            path,
        )

    @staticmethod
    def detect(path: Path) -> bool:
        return path.name.lower().endswith(COMPRESSION_EXT) or is_compressed_magic(path)

    def prepare(self, target: target.Target) -> Path:
        filename = self.path.name.removesuffix(".gz")
        vfs = VirtualFilesystem()
        vfs.map_file_fh(filename, fsutil.open_decompress(self.path))

        return vfs.path(filename)


def is_compressed_magic(path: Path) -> bool:
    """
    Check if this is a compressed file based on the magic
        Based on the magic check from fsutil.open_decompress
    """

    file = path.open("rb")

    magic = file.read(5)
    file.seek(0)

    # Gzip
    if magic[:2] == b"\x1f\x8b":
        return True

    # LZMA
    if magic[:5] == b"\xfd7zXZ":
        return True

    # BZ2
    if magic[:3] == b"BZh" and 0x31 <= magic[3] <= 0x39:
        return True

    # ZSTD
    return magic[:4] in [b"\xfd\x2f\xb5\x28", b"\x28\xb5\x2f\xfd"]
