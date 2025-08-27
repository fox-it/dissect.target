from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.loader import Loader
from dissect.target.loaders.dir import find_and_map_dirs, find_dirs, map_dirs
from dissect.target.loaders.tar import TarSubLoader
from dissect.target.loaders.zip import ZipSubLoader

if TYPE_CHECKING:
    import tarfile as tf
    import zipfile as zf
    from pathlib import Path

    from dissect.target.target import Target

log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "[root]"
UAC_CHECK_FILE = "uac.log"


class UacLoader(Loader):
    """Loader for extracted UAC collections.

    References:
        - https://github.com/tclahr/uac
        - https://tclahr.github.io/uac-docs/
    """

    @staticmethod
    def detect(path: Path) -> bool:
        return path.joinpath(FILESYSTEMS_ROOT).exists() and path.joinpath(UAC_CHECK_FILE).exists()

    def map(self, target: Target) -> None:
        os_type, dirs = find_dirs(self.absolute_path.joinpath(FILESYSTEMS_ROOT))
        map_dirs(target, dirs, os_type)


class UacTarSubloader(TarSubLoader):
    """Loader for tar-based UAC collections.

    References:
        - https://github.com/tclahr/uac
        - https://tclahr.github.io/uac-docs/
    """

    FS_ROOT_TUPLE = (f"/{FILESYSTEMS_ROOT}/", f"{FILESYSTEMS_ROOT}/")

    @staticmethod
    def detect(path: Path, tarfile: tf.TarFile) -> bool:
        return any(member.name.startswith(UacTarSubloader.FS_ROOT_TUPLE) for member in tarfile.getmembers())

    def map(self, target: Target) -> None:
        vol = TarFilesystem(tarfile=self.tar, base=FILESYSTEMS_ROOT, fh=self.tar.fileobj)
        target.filesystems.add(vol)


class UacZipSubLoader(ZipSubLoader):
    """Loader for zip-based UAC collections.

    References:
        - https://github.com/tclahr/uac
        - https://tclahr.github.io/uac-docs/
    """

    @staticmethod
    def detect(path: Path, zipfile: zf.Path) -> bool:
        return zipfile.joinpath(FILESYSTEMS_ROOT).exists() and zipfile.joinpath(UAC_CHECK_FILE).exists()

    def map(self, target: Target) -> None:
        path = self.zip.joinpath(FILESYSTEMS_ROOT)
        find_and_map_dirs(target, path)
