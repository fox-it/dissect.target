from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Union

from dissect.target import target
from dissect.target.filesystem import TarFilesystem
from dissect.target.loader import Loader
from dissect.target.loaders.dir import find_and_map_dirs

log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "fs"


def _get_root(path: Union[Path, str]):
    if path.suffix == ".zip":
        return zipfile.Path(path.open("rb"))
    elif path.suffix == ".tar":
        return TarFilesystem(path.open("rb")).path()
    elif path.suffix in [".tar.gz", ".tgz"]:
        log.warning(
            f"Tar file {path!r} is compressed, which will affect performance. "
            "Consider uncompressing the archive before passing the tar file to Dissect."
        )
        return TarFilesystem(path.open("rb")).path()
    else:
        return path


class AcquireLoader(Loader):
    """
    Load acquire collect files.
        Supports both the zip and tar output
        Only compatible with acquire >= 3.12 due to changed structure
    """

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)

        self.root = _get_root(path)

    @staticmethod
    def detect(path: Path) -> bool:
        path = _get_root(path)

        return path.joinpath(FILESYSTEMS_ROOT).exists()

    def map(self, target: target.Target) -> None:
        find_and_map_dirs(
            target,
            self.root.joinpath(FILESYSTEMS_ROOT),
        )
