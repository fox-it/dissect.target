from pathlib import Path

from dissect.target import Target, container
from dissect.target.loader import Loader


class RawLoader(Loader):
    @staticmethod
    def detect(path: Path) -> bool:
        return not path.is_dir()

    def map(self, target: Target):
        target.disks.add(container.open(self.path))
