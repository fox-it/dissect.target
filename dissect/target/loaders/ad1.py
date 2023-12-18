from dissect.evidence import ad1

from dissect.target import filesystem
from dissect.target.loader import Loader


class AD1Loader(Loader):
    """Load AccessData's forensic image format (AD1) files."""

    def __init__(self, path, **kwargs):
        path = path.resolve()

        super().__init__(path)
        self.ad1 = ad1.AD1(path.open("rb"))

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".ad1"

    def map(self, target):
        pass


class AD1File(filesystem.VirtualFile):
    def open(self):
        return self.entry.open()
