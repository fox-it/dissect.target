from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.hypervisor import pvs

from dissect.target.containers.hdd import HddContainer
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from dissect.target import Target


class PvsLoader(Loader):
    """Parallels VM configuration file (config.pvs)."""

    def __init__(self, path: Path, **kwargs):
        path = path.resolve()

        super().__init__(path)
        self.pvs = pvs.PVS(path.open("rt"))
        self.base_dir = path.parent

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".pvs"

    def map(self, target: Target) -> None:
        for disk in self.pvs.disks():
            path = self.base_dir.joinpath(disk)
            try:
                target.disks.add(HddContainer(path))
            except Exception:
                target.log.exception("Failed to load HDD: %s", disk)
