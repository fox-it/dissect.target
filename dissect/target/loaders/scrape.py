from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.util import stream

from dissect.target import filesystem
from dissect.target.helpers import scrape
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystems.extfs import ExtFilesystem
    from dissect.target.filesystems.ntfs import NtfsFilesystem
    from dissect.target.filesystems.squashfs import SquashFSFilesystem
    from dissect.target.target import Target

BLOCK_SIZE = 64 * 0x100000  # 64 MiB

NTFS_NEEDLE = b"\xeb\x52\x90NTFS    \x00"
EXTFS_NEEDLE = b"\xff\xff\x53\xef"
SQUASHFS_NEEDLE = b"hsqs"
# Needles for various JFFS2_MAGIC_BITMASK/JFFS2_OLD_MAGIC_BITMASK and JFFS2_NODETYPE_*
JFFS2_NEEDLES = [
    # JFFS2_MAGIC_BITMASK and ...
    b"\x85\x19\x01\xe0",  # JFFS2_NODETYPE_DIRENT
    b"\x85\x19\x02\xe0",  # JFFS2_NODETYPE_INODE
    b"\x85\x19\x03\x20",  # JFFS2_NODETYPE_CLEANMARKER
    # JFFS2_OLD_MAGIC_BITMASK and ...
    b"\x84\x19\x01\xe0",  # JFFS2_NODETYPE_DIRENT
    b"\x84\x19\x02\xe0",  # JFFS2_NODETYPE_INODE
    b"\x84\x19\x03\x20",  # JFFS2_NODETYPE_CLEANMARKER
]

MAX_JFFS2_PAGE_SIZE = 0x20000

NEEDLES = [NTFS_NEEDLE, EXTFS_NEEDLE, SQUASHFS_NEEDLE, *JFFS2_NEEDLES]

NEEDLE_OFFSETS = {
    # The extfs needle is 54 kiB from the start of the extfs volume
    EXTFS_NEEDLE: 54 * 1024
}


def _size_ntfs(fs: NtfsFilesystem) -> int:
    return fs.ntfs.boot_sector.NumberSectors * fs.ntfs.sector_size


def _size_extfs(fs: ExtFilesystem) -> int:
    return fs.extfs.block_count * fs.extfs.block_size


def _size_squashfs(fs: SquashFSFilesystem) -> int:
    return fs.squashfs.sb.bytes_used


# This is a mapping of needles to functions that calculate the size of the filesystem
FS_SIZE = {
    NTFS_NEEDLE: _size_ntfs,
    EXTFS_NEEDLE: _size_extfs,
    SQUASHFS_NEEDLE: _size_squashfs,
}


def _find_jffs2_size(fh: BinaryIO, offset: int) -> int:
    fh.seek(offset + 4)

    current_eof = offset + ((int.from_bytes(fh.read(4), "little") + 3) & ~3)
    for _, node_offset, _ in scrape.find_needles(
        fh, JFFS2_NEEDLES, start=current_eof, lock_seek=False, block_size=BLOCK_SIZE
    ):
        if node_offset - current_eof > MAX_JFFS2_PAGE_SIZE:
            break

        fh.seek(node_offset + 4)
        current_eof = node_offset + ((int.from_bytes(fh.read(4), "little") + 3) & ~3)

        fh.seek(current_eof)

    return current_eof - offset


class ScrapeLoader(Loader):
    """Load files by scraping for known filesystem signatures."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fh = self.path.open("rb")

    @staticmethod
    def detect(path: Path) -> bool:
        """This loader can only be activated with the URI-scheme ``scrape://<file>``."""
        return False

    def map(self, target: Target) -> None:
        for needle, offset, _ in scrape.find_needles(self.fh, NEEDLES, start=0, lock_seek=False, block_size=BLOCK_SIZE):
            current_offset = self.fh.tell()
            size = None

            if needle in JFFS2_NEEDLES:
                # JFFS2 doesn't have a "size", so try to determine it with some heuristics
                size = _find_jffs2_size(self.fh, offset)
                volume = stream.RangeStream(self.fh, offset, offset + size)
            else:
                volume = stream.RelativeStream(self.fh, offset - NEEDLE_OFFSETS.get(needle, 0))

            try:
                fs = filesystem.open(volume)
            except Exception:
                self.fh.seek(current_offset)
                continue

            # If we know how to calculate the size of the filesystem, do that so we skip over it
            # If we don't (but we succeeded in opening it), assume that the filesystem left the file pointer at
            # the end of the filesystem and continue from there (e.g. JFFS2)
            if needle in FS_SIZE:
                size = FS_SIZE[needle](fs)

            if size is not None:
                self.fh.seek(offset + size)

            target.filesystems.add(fs)
