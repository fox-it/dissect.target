from dissect.hypervisor import ovf

from dissect.target.containers.vmdk import VmdkContainer
from dissect.target.loader import Loader


class OvfLoader(Loader):
    def __init__(self, path, **kwargs):
        path = path.resolve()

        super().__init__(path)
        with open(path) as fh:
            self.ovf = ovf.OVF(fh)
        self.base_dir = path.parent

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".ovf"

    def map(self, target):
        for disk in self.ovf.disks():
            try:
                path = disk.replace("\\", "/")
                _, _, fname = path.rpartition("/")
                fh = self.open(fname)
            except IOError:
                target.log.exception("Failed to find disk: %s", disk)
                continue

            target.disks.add(VmdkContainer(fh))

    def open(self, path):
        return self.base_dir.joinpath(path).open("rb")
