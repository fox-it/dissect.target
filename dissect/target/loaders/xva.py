from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.archive import xva

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class XvaLoader(Loader):
    """Load Citrix Hypervisor XVA format files.

    References:
        - https://docs.citrix.com/en-us/citrix-hypervisor/vms/import-export.html#xva-format
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.xva = xva.XVA(path.open("rb"))

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".xva"

    def map(self, target: Target) -> None:
        for ref in self.xva.disks():
            disk = self.xva.open(ref)

            target.disks.add(RawContainer(disk))
