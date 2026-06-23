from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.evidence.aff4 import AFF4

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class Aff4Loader(Loader):
    """Load Advanced Forensic File Format 4 (AFF4) files.

    References:
        - https://github.com/aff4/Standard
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.aff4 = AFF4(path)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".aff4"

    def map(self, target: Target) -> None:
        for image in self.aff4.images():
            target.disks.add(RawContainer(image.open()))
