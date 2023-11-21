from dissect.hypervisor import xva

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader


class XvaLoader(Loader):
    """Load Citrix Hypervisor XVA format files.

    References:
        - https://docs.citrix.com/en-us/citrix-hypervisor/vms/import-export.html#xva-format
    """

    def __init__(self, path, **kwargs):
        path = path.resolve()
        super().__init__(path)
        self.xva = xva.XVA(path.open("rb"))

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".xva"

    def map(self, target):
        for ref in self.xva.disks():
            disk = self.xva.open(ref)

            target.disks.add(RawContainer(disk))
