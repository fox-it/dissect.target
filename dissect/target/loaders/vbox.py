from dissect.hypervisor import vdi

from dissect.target.containers.vdi import VdiContainer
from dissect.target.loader import Loader


class VboxLoader(Loader):
    def __init__(self, path, **kwargs):
        path = path.resolve()

        super().__init__(path)
        with path.open("r") as fh:
            self.vbox = vdi.Vbox(fh)
        self.base_dir = path.parent

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".vbox"

    def map(self, target):
        for disk, _ in self.vbox.snapshots():
            parent = self.open(disk)
            target.disks.add(VdiContainer(parent))

    def open(self, path):
        return self.base_dir.joinpath(path).open("rb")
