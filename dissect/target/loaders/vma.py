from dissect.hypervisor import vma

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader


class VmaLoader(Loader):
    """Load Proxmox Virtual Machine Archive (VMA) files.

    References:
        - https://pve.proxmox.com/wiki/VMA
    """

    def __init__(self, path, **kwargs):
        path = path.resolve()
        super().__init__(path)
        self.vma = vma.VMA(open(path, "rb"))

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".vma"

    def map(self, target):
        for device in self.vma.devices():
            target.disks.add(RawContainer(device.open()))
