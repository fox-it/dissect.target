from dissect.util import stream

from dissect.target import filesystem
from dissect.target.loader import Loader

BLOCK_SIZE = 64 * 0x100000  # 64 MiB

NTFS_NEEDLE = b"\xeb\x52\x90NTFS    \x00"
EXTFS_NEEDLE = b"\xff\xff\x53\xef"
# The extfs needle is 54 kiB from the start of the extfs volume
EXTFS_NEEDLE_OFFSET = 0x36 * 1024
FS_NEEDLES = [NTFS_NEEDLE, EXTFS_NEEDLE]


def scrape_pos(fp, needles, block_size=BLOCK_SIZE):
    while True:
        file_pos = fp.tell()
        block = fp.read(block_size)

        if not block:
            break

        for needle in needles:
            block_pos = -1
            while True:
                block_pos = block.find(needle, block_pos + 1)
                if block_pos == -1:
                    break

                offset = file_pos + block_pos
                yield needle, offset


class PhobosLoader(Loader):
    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".eight"

    def map(self, target):
        fh = self.path.open("rb")

        fs_idx = 0
        for needle, offset in scrape_pos(fh, FS_NEEDLES):
            cur_seek = fh.tell()

            try:
                if needle == NTFS_NEEDLE:
                    volume = stream.RelativeStream(fh, offset)
                    fs = filesystem.open(volume)
                    size = fs.ntfs.header.sector_count_64 * fs.ntfs.header.bytes_per_sector
                elif needle == EXTFS_NEEDLE:
                    volume = stream.RelativeStream(fh, offset - EXTFS_NEEDLE_OFFSET)
                    fs = filesystem.open(volume)
                    size = fs.extfs.block_count * fs.extfs.block_size

                target.filesystems.add(fs)
                target.fs.mount(f"fs{fs_idx}", fs)
                fs_idx += 1

                fh.seek(offset + size)
            except Exception:
                fh.seek(cur_seek)
