from pathlib import Path

from dissect.target import container
from dissect.target.loader import Loader


class RawLoader(Loader):
    @staticmethod
    def detect(path: Path):
        return not path.is_dir()

    def map(self, target):
        target.disks.add(container.open(self.path))
