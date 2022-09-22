from dissect.hypervisor import vmx

from dissect.target.containers.vmdk import VmdkContainer
from dissect.target.loader import Loader


class VmxLoader(Loader):
    def __init__(self, path, **kwargs):
        path = path.resolve()

        super().__init__(path)
        self.vmx = vmx.VMX.parse(path.read_text())
        self.base_dir = path.parent

    @staticmethod
    def detect(path):
        return path.suffix.lower() in (".vmx", ".vmtx")

    def map(self, target):
        for disk in self.vmx.disks():
            path = self.base_dir.joinpath(disk)
            try:
                target.disks.add(VmdkContainer(path))
            except Exception:  # noqa
                target.log.exception("Failed to load VMDK: %s", disk)
