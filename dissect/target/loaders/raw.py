from pathlib import Path

from dissect.target import container
from dissect.target.loader import Loader
from dissect.target.target import Target


class RawLoader(Loader):
    """Load raw container files such as disk images."""

    @staticmethod
    def detect(path: Path) -> bool:
        return not path.is_dir()

    def map(self, target: Target) -> None:
        target.disks.add(container.open(self.path))
