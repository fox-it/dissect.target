from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.ngc.protector import NGCProtector
from dissect.target.plugins.os.windows.ngc.util import read_dat

if TYPE_CHECKING:
    from pathlib import Path


class NGCProvider:
    """Windows NGC Provider implementation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.name = read_dat(path.joinpath("7.dat"))
        self.sid = read_dat(path.joinpath("1.dat"))

    def __repr__(self) -> str:
        return f"<NGCProvider name={self.name} user={self.sid} path={self.path}"

    @property
    def protectors(self) -> list[NGCProtector]:
        """Return all NGC protectors in this provider."""
        return [NGCProtector(self, path) for path in self.path.joinpath("Protectors").iterdir()]
