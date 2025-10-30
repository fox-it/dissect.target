from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.evidence.ad1.ad1 import find_files

from dissect.target.filesystems.ad1 import AD1Filesystem
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class AD1Loader(Loader):
    """Access Data ``.ad`` loader."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)
        self.segment_files = find_files(path)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".ad1"

    def map(self, target: Target) -> None:
        fs = AD1Filesystem([segment.open("rb") for segment in self.segment_files])
        target.filesystems.add(fs)
        # TODO: Detect NTFS
        # TODO: Handle custom content images with multiple sources
