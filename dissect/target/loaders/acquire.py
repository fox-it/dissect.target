from __future__ import annotations

import logging
import zipfile
from pathlib import Path

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.filesystems.zip import ZipFilesystem
from dissect.target.loader import Loader
from dissect.target.loaders.dir import find_and_map_dirs
from dissect.target.target import Target

log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "fs"


def _get_root(path: Path):
    if path.is_file():
        fh = path.open("rb")
        if TarFilesystem._detect(fh):
            return TarFilesystem(fh).path()

        # test this
        if ZipFilesystem._detect(fh):
            return zipfile.Path(path.open("rb"))

    return None


class AcquireLoader(Loader):
    def __init__(self, path: Path, **kwargs):
        super().__init__(path)

        self.root = _get_root(path)

    @staticmethod
    def detect(path: Path) -> bool:
        root = _get_root(path)

        if not root:
            return False

        return root.joinpath(FILESYSTEMS_ROOT).exists()

    def map(self, target: Target) -> None:
        find_and_map_dirs(
            target,
            self.root.joinpath(FILESYSTEMS_ROOT)
        )
