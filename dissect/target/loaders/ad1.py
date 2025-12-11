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
        """Map the detected segment files as an :class:`AD1Filesystem` to the target.

        Currently does not detect NTFS / case-insensitive filesystems or custom content
        images with multiple sources.
        """
        try:
            fs = AD1Filesystem(find_files(self.path))
            target.filesystems.add(fs)

        except ValueError as e:
            target.log.error("Unable to map AD1: %s", e)  # noqa: TRY400
