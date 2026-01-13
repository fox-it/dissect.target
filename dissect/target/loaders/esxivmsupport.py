from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.logging import get_logger
from dissect.target.loader import Loader
from dissect.target.loaders.dir import map_dirs
from dissect.target.loaders.tar import TarSubLoader
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    import tarfile as tf
    from pathlib import Path

    from dissect.target.target import Target


log = get_logger(__name__)
# From tech support readme
# Files/Directories of Interest:
# ------------------------------
#
# error.log: log containing errors that ocurred while running vm-support
# action.log: a log of all commands, and/or actions run during vm-support
# commands: a directory containing output files for all commands run
#
# All other directories and files should be mirrors of the the ESXi system
# vm-support was run on.

EXPECTED_FILES_OR_DIR = ["etc/vmware/esx.conf", "error.log", "action.log"]


class EsxiVmSupportLoader(Loader):
    """Loader for extracted ESXi vm-support

    References:
        - https://knowledge.broadcom.com/external/article/313542
    """

    @staticmethod
    def detect(path: Path) -> bool:
        if not path.is_dir():
            return False
        root_dir = next(path.iterdir())
        return all(root_dir.joinpath(f).exists() for f in EXPECTED_FILES_OR_DIR)

    def map(self, target: Target) -> None:
        map_dirs(target, [next(self.absolute_path.iterdir())], OperatingSystem.ESXI)


class EsxiVmSupportTarSubloader(TarSubLoader):
    """Loader for tar-based ESXi vm-support.

    References:
        - https://knowledge.broadcom.com/external/article/313542
    """

    @staticmethod
    def detect(path: Path, tarfile: tf.TarFile) -> bool:
        if not (names := tarfile.getnames()):
            return False
        root = names[0].split("/")[0]
        required_paths = {f"{root}/{f}" for f in EXPECTED_FILES_OR_DIR}
        return required_paths.issubset(names)

    def map(self, target: Target) -> None:
        fs = TarFilesystem(tarfile=self.tar, base=self.tar.getnames()[0].split("/")[0], fh=self.tar.fileobj)
        target.filesystems.add(fs)
