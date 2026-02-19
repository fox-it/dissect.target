from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import LOADERS, Loader

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import target

GZ_EXT = (".gz",)


class GzipLoader(Loader):
    """Allow loading Gzip compressed files. Actual loading is handled by the normal loaders."""

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.name.lower().endswith(GZ_EXT)

    def map(self, target: target.Target) -> None:
        filename = self.path.name.removesuffix(".gz")
        vfs = VirtualFilesystem()
        vfs.map_file(filename, self.path, "gzip")
        path = vfs.get(filename)

        for candidate in LOADERS:
            try:
                target.log.info("Testing sub-loader %s", candidate.__name__)
                if candidate.detect(path):
                    self.subloader = candidate(path)
                    self.subloader.map(target)
                    break
            except Exception as e:
                target.log.debug("Failed to use loader %s", candidate)
                target.log.debug("", exc_info=e)
