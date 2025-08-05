from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.hypervisor import vbox

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
            self.vbox = vbox.VBox(fh)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".vbox"

    def map(self, target: Target) -> None:
        for disk in self.vbox.disks():
            target.disks.add(container.open(self.base_path.joinpath(disk)))
