from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target import container
from dissect.target.exceptions import TargetPathNotFoundError
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class RawLoader(Loader):
    """Load raw container files such as disk images."""

    def __init__(self, path: Path, **kwargs):
        if not path.exists():
            raise TargetPathNotFoundError("Provided target path does not exist")

        super().__init__(path, **kwargs)

    @staticmethod
    def detect(path: Path) -> bool:
        return not path.is_dir()

    def map(self, target: Target) -> None:
        target.disks.add(container.open(self.path))
