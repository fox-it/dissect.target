from pathlib import Path

from dissect.hypervisor import ovf

from dissect.target import container
from dissect.target.loader import Loader
from dissect.target.target import Target


class OvfLoader(Loader):
    """Load Open Virtualization Format (OVF) files.

    References:
        - https://en.wikipedia.org/wiki/Open_Virtualization_Format
    """

    def __init__(self, path: Path, **kwargs):
        path = path.resolve()
        super().__init__(path)

        with path.open("r") as fh:
            self.ovf = ovf.OVF(fh)
        self.base_dir = path.parent

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".ovf"

    def map(self, target: Target) -> None:
        for disk in self.ovf.disks():
            disk = disk.replace("\\", "/")
            _, _, fname = disk.rpartition("/")
            path = self.base_dir.joinpath(fname)

            try:
                target.disks.add(container.open(path))
            except Exception:
                target.log.exception("Failed to load disk: %s", disk)
