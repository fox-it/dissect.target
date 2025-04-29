from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.hypervisor.descriptor.vbox import VBox

from dissect.target import container
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class VBoxLoader(Loader):
    """Load Oracle VirtualBox files."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        with path.open("r") as fh:
            self.vbox = VBox(fh)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".vbox"

    def map(self, target: Target) -> None:
        for disk in self.vbox.disks():
            parent = self.base_path.joinpath(disk).open("rb")
            target.disks.add(container.open(parent))
