from pathlib import Path
from typing import TYPE_CHECKING

try:
    from ruamel.yaml import YAML
except ImportError:
    raise ImportError("Missing ruamel.yaml dependency")

from dissect.target import container
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from dissect.target.target import Target


class TargetLoader(Loader):
    """Load target files."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path)
        self.base_dir = path.parent
        self.definition = YAML(typ="safe").load(path.open("rb"))

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".target"

    def map(self, target: Target) -> None:
        for disk in self.definition["disks"]:
            target.disks.add(container.open(disk))
