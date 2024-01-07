from pathlib import Path

from dissect.target.exceptions import LoaderError
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.loaders.ovf import OvfLoader


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

        super().__init__(ovf_path)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".ova"
