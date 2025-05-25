from __future__ import annotations

import logging
import tarfile as tf
import zipfile as zf
from pathlib import Path

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.loaders.dir import find_and_map_dirs
from dissect.target.loaders.tar import TarSubLoader
from dissect.target.loaders.zip import ZipSubLoader
from dissect.target.target import Target

log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "fs"
FILESYSTEMS_LEGACY_ROOT = "sysvol"


class AcquireTarSubLoader(TarSubLoader):
    """Loader for tar-based Acquire collections."""

    @staticmethod
    def detect(tarfile: tf.TarFile) -> bool:
        for member in tarfile.getmembers():
            if member.name.startswith((f"/{FILESYSTEMS_ROOT}/", f"{FILESYSTEMS_ROOT}/",
                                           f"/{FILESYSTEMS_LEGACY_ROOT}/", f"{FILESYSTEMS_LEGACY_ROOT}/")):
                return True
        return False

    def map(self, target: Target) -> None:
        tar_fs = TarFilesystem(tarfile=self.tar).path()
        map_acquire(target, tar_fs)


class AcquireZipSubLoader(ZipSubLoader):
    """Loader for zip-based Acquire collections."""

    @staticmethod
    def detect(zipfile: zf.Path) -> bool:
        return zipfile.joinpath(FILESYSTEMS_ROOT).exists() or zipfile.joinpath(FILESYSTEMS_LEGACY_ROOT).exists()

    def map(self, target: Target) -> None:
        map_acquire(target, self.zip)


def map_acquire(target: Target, path: Path):
    """
    Map Acquire filestructure
    """
    if path.joinpath(FILESYSTEMS_ROOT).exists():
        path = path.joinpath(FILESYSTEMS_ROOT)
    find_and_map_dirs(target, path)
