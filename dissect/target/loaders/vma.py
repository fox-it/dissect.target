from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.archive import vma

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class VmaLoader(Loader):
    """Load Proxmox Virtual Machine Archive (VMA) files.

    References:
        - https://pve.proxmox.com/wiki/VMA
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.vma = vma.VMA(path.open("rb"))

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".vma"

    def map(self, target: Target) -> None:
        for device in self.vma.devices():
            target.disks.add(RawContainer(device.open()))
