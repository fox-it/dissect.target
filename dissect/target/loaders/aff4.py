from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.evidence.aff4 import AFF4

from dissect.target.containers.raw import RawContainer
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.evidence.aff4 import ContiguousImage
    from dissect.target.target import Target

# Image types that represent a full (disk) image and can be mapped as a raw container.
DISK_IMAGE_TYPES = ("DiskImage", "DiscontiguousImage")


class AFF4Loader(Loader):
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

    def _images(self) -> Iterator[ContiguousImage]:
        """Yield all disk-like images in the AFF4 container, de-duplicated by ID."""
        seen = set()
        for image_type in DISK_IMAGE_TYPES:
            for image in self.aff4.information.find(image_type):
                if image.id not in seen:
                    seen.add(image.id)
                    yield image

    def map(self, target: Target) -> None:
        for image in self._images():
            target.disks.add(RawContainer(image.open()))
