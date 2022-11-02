from dissect.hypervisor.descriptor.vbox import VBox

from dissect.target import container
from dissect.target.loader import Loader


class VBoxLoader(Loader):
    def __init__(self, path, **kwargs):
        path = path.resolve()

        super().__init__(path)
        with path.open("r") as fh:
            self.vbox = VBox(fh)
        self.base_dir = path.parent

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".vbox"

    def map(self, target):
        for disk in self.vbox.disks():
            parent = self.open(disk)
            target.disks.add(container.open(parent))

    def open(self, path):
        return self.base_dir.joinpath(path).open("rb")
