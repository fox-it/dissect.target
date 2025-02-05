import re
from pathlib import Path
from typing import Iterator

from dissect.target import target, Target, container
from dissect.target.filesystems.vbk import VbkFilesystem
from dissect.target.loader import Loader
from dissect.target.loaders.vmx import VmxLoader


class VbkLoader(Loader):
    """Load Veaam Backup (VBK) files."""

    def __init__(self, path, **kwargs):
        super().__init__(path, **kwargs)
        self.path = path

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".vbk"

    @staticmethod
    def find_all(path: Path, **kwargs) -> Iterator[Path]:
        vbkfs = VbkFilesystem(path.open("rb"))
        for _, _, files in vbkfs.walk_ext("/"):
            for file in files:
                is_vmx = file.path.lower().endswith(".vmx")
                is_disk = re.match(r'.{8}-.{4}-.{4}-.{4}-.{12}', file.name)

                if is_vmx or is_disk:
                    yield vbkfs.get(file.path)

    def map(self, target: target.Target) -> None:
        is_vmx = self.path.name.lower().endswith(".vmx")
        is_disk = re.match(r'.{8}-.{4}-.{4}-.{4}-.{12}', self.path.name)

        if is_vmx:
            # TODO: how to open this vmx
            #VmxLoader(self.path).map(target)
            pass
        if is_disk:
            target.disks.add(self.path.open())



