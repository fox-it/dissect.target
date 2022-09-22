from dissect.hypervisor import xva

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader


class XvaLoader(Loader):
    def __init__(self, path, **kwargs):
        path = path.resolve()
        super().__init__(path)
        self.xva = xva.XVA(open(path, "rb"))

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".xva"

    def map(self, target):
        for ref in self.xva.disks():
            disk = self.xva.open(ref)

            target.disks.add(RawContainer(disk))
