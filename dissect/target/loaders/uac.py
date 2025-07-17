from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from dissect.target import filesystem
from dissect.target.filesystems.tar import TarFilesystemDirectoryEntry, TarFilesystemEntry
from dissect.target.helpers import fsutil
from dissect.target.loaders.dir import DirLoader, find_and_map_dirs, find_dirs, map_dirs
from dissect.target.loaders.tar import TarSubLoader
from dissect.target.loaders.zip import ZipSubLoader

if TYPE_CHECKING:
    import tarfile as tf
    import zipfile as zf
    from pathlib import Path

    from dissect.target import Target

log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "[root]"
UAC_CHECK_FILE = "uac.log"


def find_fs_directories(path: Path) -> tuple[str, list[Path]]:
    fs_root = path.joinpath(FILESYSTEMS_ROOT)
    return find_dirs(fs_root)


class UACLoader(DirLoader):
    """UAC forensic image files (uncompressed or as .tar.gz or .zip)
    .
    References:
        - https://github.com/tclahr/uac
        - https://tclahr.github.io/uac-docs/
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path)
        self.root = path.absolute()

    @staticmethod
    def detect(path: Path) -> bool:
        return path.joinpath(FILESYSTEMS_ROOT).exists() and path.joinpath(UAC_CHECK_FILE).exists()

    def map(self, target: Target) -> None:
        os_type, dirs = find_fs_directories(self.root)
        map_dirs(target, dirs, os_type)


class UacTarSubloader(TarSubLoader):
    @staticmethod
    def detect(tarfile: tf.TarFile) -> bool:
        for member in tarfile.getmembers():
            if member.name.startswith((f"/{FILESYSTEMS_ROOT}/", f"{FILESYSTEMS_ROOT}/")):
                return True
        return False

    def map(self, target: Target) -> None:
        # volumes = TarFilesystemDirectoryEntry()
        vol = filesystem.VirtualFilesystem(case_sensitive=False)
        vol.tar = self.tar
        for member in self.tar.getmembers():
            if member.name == ".":
                continue

            if member.name.startswith((f"/{FILESYSTEMS_ROOT}/", f"{FILESYSTEMS_ROOT}/")):
                # Current acquire
                parts = member.name.replace(f"{FILESYSTEMS_ROOT}/", "").split("/")
                if parts[0] == "":
                    parts.pop(0)

                mname = "/".join(parts)
                entry_cls = TarFilesystemDirectoryEntry if member.isdir() else TarFilesystemEntry
                entry = entry_cls(vol, fsutil.normpath(mname), member)
                vol.map_file_entry(entry.path, entry)
        target.filesystems.add(vol)


class UacZipSubLoader(ZipSubLoader):
    """Loader for zip-based Acquire collections."""

    @staticmethod
    def detect(zipfile: zf.Path) -> bool:
        return zipfile.joinpath(FILESYSTEMS_ROOT).exists() and zipfile.joinpath(UAC_CHECK_FILE).exists()

    def map(self, target: Target) -> None:
        path = self.zip
        if path.joinpath(FILESYSTEMS_ROOT).exists():
            path = path.joinpath(FILESYSTEMS_ROOT)
        find_and_map_dirs(target, path)
