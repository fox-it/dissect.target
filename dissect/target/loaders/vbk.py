from dissect.target.filesystems.vbk import VBKFilesystem
from dissect.target.loader import Loader


class VBKLoader(Loader):
    """Load Veaam Backup (VBK) files.
    """

    def __init__(self, path, **kwargs):
        super().__init__(path, **kwargs)
        self.path = path

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".vbk"

    def map(self, target):
        fs = VBKFilesystem(self.path.open("rb"))
        target.filesystems.add(fs)
