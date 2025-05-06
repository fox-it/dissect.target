from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader
from dissect.target.plugins.os.default._os import DefaultOSPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


class DirectLoader(Loader):
    def __init__(self, paths: list[str | Path]):
        self.paths = [(Path(path) if not isinstance(path, Path) else path).resolve() for path in paths]

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        vfs = VirtualFilesystem()
        for path in self.paths:
            if path.is_file():
                vfs.map_file(str(path), str(path))
            elif path.is_dir():
                vfs.map_dir(str(path), str(path))

        target.filesystems.add(vfs)
        target._os_plugin = DefaultOSPlugin
