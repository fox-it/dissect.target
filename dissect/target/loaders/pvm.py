from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.loaders.pvs import PvsLoader

if TYPE_CHECKING:
    from pathlib import Path


class PvmLoader(PvsLoader):
    """Parallels VM directory (.pvm)."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path.joinpath("config.pvs"), **kwargs)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.is_dir() and path.suffix.lower() == ".pvm" and path.joinpath("config.pvs").exists()
