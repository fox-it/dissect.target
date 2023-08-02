from pathlib import Path

from dissect.target import container
from dissect.target.loader import Loader
from dissect.target.target import Target


class MultiRawLoader(Loader):
    """Load multiple raw containers as a single target (i.e. a multi-disk system)."""

    @staticmethod
    def detect(path: Path) -> bool:
        if not path.exists() and "+" in str(path):
            # Get a path to root with the same path type for TargetPath compatibility
            root = path.joinpath("/")
            return all(root.joinpath(subpath).exists() for subpath in str(path).split("+"))

        return False

    def map(self, target: Target) -> None:
        root = self.path.joinpath("/")
        for subpath in str(self.path).split("+"):
            target.disks.add(container.open(root.joinpath(subpath)))
