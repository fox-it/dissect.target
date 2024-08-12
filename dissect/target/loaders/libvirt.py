from pathlib import Path

from defusedxml import ElementTree

import dissect.target.container as container
from dissect.target import Target
from dissect.target.loader import Loader


class LibvirtLoader(Loader):
    """Load libvirt xml configuration files."""

    def __init__(self, path: Path, **kwargs):
        path = path.resolve()
        self.base_dir = path.parent
        super().__init__(path)

    @staticmethod
    def detect(path: Path) -> bool:
        if path.suffix.lower() != ".xml":
            return False

        with path.open("rb") as fh:
            lines = fh.read(512).split(b"\n")
            # From what I've seen, these are are always at the start of the file
            # If its generated using virt-install
            needles = [b"<domain", b"<name>", b"<uuid>"]
            return all(any(needle in line for line in lines) for needle in needles)

    def map(self, target: Target) -> None:
        xml_data = ElementTree.XML(self.path.read_text())
        for disk in xml_data.findall("devices/disk/source"):
            if not (file := disk.get("file")):
                continue

            path = Path(file)

            for part in [path.name, file]:
                if (target_file := self.base_dir.joinpath(part)).exists():
                    target.disks.add(container.open(target_file))
                    break
