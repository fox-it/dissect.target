from pathlib import Path

from dissect.util import cpio

from dissect.target import Target
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.loader import Loader


class CpioLoader(Loader):
    """Load (compressed) CPIO files."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path)

        fh = open_decompress(path, "rb")
        self.cpio = TarFilesystem(fh, tarinfo=cpio.CpioInfo)

    @staticmethod
    def detect(path: Path) -> bool:
        magic = path.open("rb").read(6)

        # gzip, bz2 or zstd
        if magic[:2] == b"\x1f\x8b" or magic[:4] in [b"\xfd\x2f\xb5\x28", b"\x28\xb5\x2f\xfd"]:
            magic = open_decompress(path, "rb").read(6)

        return magic in [b"070701", b"070707", b"070702"] or magic[:2] in [b"\x71\xc7", b"\xc7\x71"]

    def map(self, target: Target) -> None:
        target.filesystems.add(self.cpio)
        target.fs.mount("/", self.cpio)
