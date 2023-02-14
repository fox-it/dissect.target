try:
    import yaml
except ImportError:
    raise ImportError("Missing PyYAML dependency")

from dissect.target import container
from dissect.target.loader import Loader


class TargetLoader(Loader):
    def __init__(self, path, **kwargs):
        super().__init__(path)
        self.base_dir = path.parent
        self.definition = yaml.safe_load(path.open("rb"))

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".target"

    def map(self, target):
        for disk in self.definition["disks"]:
            target.disks.add(container.open(disk))

    def open(self, path):
        return self.base_dir.joinpath(path).open("rb")
