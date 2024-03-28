from pathlib import Path

from defusedxml import ElementTree

import dissect.target.container as container
from dissect.target import Target
from dissect.target.loader import Loader


class LibvirtLoader(Loader):
    """Load libvirt xml configuration files."""

    def __init__(self, path: Path, **kwargs):
        path = path.resolve()

        super().__init__(path)

    @staticmethod
    def detect(path: Path) -> bool:
        if path.suffix.lower() != ".xml":
            return False

        with path.open("rb") as fh:
            return b"<domain>" in fh.read(512)

    def map(self, target: Target) -> None:
        xml_data = ElementTree.XML(self.path.read_text())
        for disk in xml_data.findall("devices/disk/source"):
            if file := disk.get("file"):
                target_file = self.path.joinpath(file)
                target.disks.add(container.open(target_file))
