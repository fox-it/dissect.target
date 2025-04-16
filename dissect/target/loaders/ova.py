from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import LoaderError
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.loaders.ovf import OvfLoader

if TYPE_CHECKING:
    from pathlib import Path


class OvaLoader(OvfLoader):
    """Load Open Virtual Appliance (OVA) files.

    References:
        - https://en.wikipedia.org/wiki/Open_Virtualization_Format
    """

    def __init__(self, path: Path, **kwargs):
        self.ova = TarFilesystem(path.open("rb"))

        ovf_path = next(self.ova.path().glob("*.ovf"), None)
        if ovf_path is None:
            raise LoaderError("Invalid OVA file (can't find .ovf)")

        super().__init__(ovf_path, **kwargs)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".ova"
