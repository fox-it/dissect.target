from pathlib import Path

from dissect.target import container
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.loader import Loader
from dissect.target.target import Target


class MultiRawLoader(Loader):
    """Load multiple raw containers as a single target (i.e. a multi-disk system).

    Use as ``/path/to/disk1+/path/to/disk2`` to load a single target with two disks.
    The disks can be anything that Dissect supports such as EWF, VMDK, etc.
    """

    @staticmethod
    def detect(path: Path) -> bool:
        if not path.exists() and "+" in str(path):
            return all(p.exists() for p in _split_paths(path))

        return False

    def map(self, target: Target) -> None:
        for subpath in _split_paths(self.path):
            target.disks.add(container.open(subpath))


def _split_paths(path: Path) -> list[Path]:
    if isinstance(path, TargetPath):
        root = path.joinpath("/")
    else:
        root = path.cwd()

    return [root.joinpath(subpath) for subpath in str(path).split("+")]
