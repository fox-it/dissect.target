from pathlib import Path

from dissect.target import target
from dissect.target.filesystems.vbk import VbkFilesystem
from dissect.target.loader import Loader


class VbkLoader(Loader):
    """Load Veaam Backup (VBK) files."""

    def __init__(self, path, **kwargs):
        super().__init__(path, **kwargs)
        self.path = path

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".vbk"

    def map(self, target: target.Target) -> None:
        fs = VbkFilesystem(self.path.open("rb"))
        target.filesystems.add(fs)
