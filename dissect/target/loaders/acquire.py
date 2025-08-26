from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from dissect.target import filesystem
from dissect.target.filesystems.tar import TarFilesystemDirectoryEntry, TarFilesystemEntry
from dissect.target.helpers import fsutil, loaderutil
from dissect.target.loaders.dir import find_and_map_dirs
from dissect.target.loaders.tar import TarSubLoader
from dissect.target.loaders.zip import ZipSubLoader

if TYPE_CHECKING:
    import tarfile as tf
    import zipfile as zf
    from pathlib import Path

    from dissect.target.target import Target


log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "fs"
FILESYSTEMS_LEGACY_ROOT = "sysvol"

ANON_FS_RE = re.compile(r"^fs[0-9]+$")


class AcquireTarSubLoader(TarSubLoader):
    """Loader for tar-based Acquire collections."""

    @staticmethod
    def detect(path: Path, tarfile: tf.TarFile) -> bool:
        for member in tarfile.getmembers():
            if member.name.startswith(
                (
                    f"/{FILESYSTEMS_ROOT}/",
                    f"{FILESYSTEMS_ROOT}/",
                    f"/{FILESYSTEMS_LEGACY_ROOT}/",
                    f"{FILESYSTEMS_LEGACY_ROOT}/",
                )
            ):
                return True
        return False

    def map(self, target: Target) -> None:
        volumes = {}

        for member in self.tar.getmembers():
            if member.name == ".":
                continue

            if member.name.startswith(("/fs/", "fs/")):
                # Current acquire
                parts = member.name.replace("fs/", "").split("/")
                if parts[0] == "":
                    parts.pop(0)
            else:
                # Legacy acquire
                parts = member.name.lstrip("/").split("/")
            volume_name = parts[0].lower()

            # NOTE: older versions of acquire would write to "sysvol" instead of a driver letter
            # Figuring out the sysvol from the drive letters is easier than the drive letter from "sysvol",
            # so this was swapped in acquire 3.12. Now we map all volumes to a drive letter and let the
            # Windows OS plugin figure out which is the sysvol
            # For backwards compatibility we're forced to keep this check, and assume that "c:" is our sysvol
            if volume_name == "sysvol":
                volume_name = "c:"

            if volume_name == "$fs$":
                if len(parts) == 1:
                    # The fs/$fs$ entry is ignored, only the directories below it are processed.
                    continue
                fs_name = parts[1]
                if ANON_FS_RE.match(fs_name):
                    parts.pop(0)
                    volume_name = f"{volume_name}/{fs_name}"

            if volume_name not in volumes:
                vol = filesystem.VirtualFilesystem(case_sensitive=False)
                vol.tar = self.tar
                volumes[volume_name] = vol
                target.filesystems.add(vol)

            volume = volumes[volume_name]
            mname = "/".join(parts[1:])

            entry_cls = TarFilesystemDirectoryEntry if member.isdir() else TarFilesystemEntry
            entry = entry_cls(volume, fsutil.normpath(mname), member)
            volume.map_file_entry(entry.path, entry)

        for vol_name, vol in volumes.items():
            loaderutil.add_virtual_ntfs_filesystem(
                target,
                vol,
                usnjrnl_path=[
                    "$Extend/$Usnjrnl:$J",
                    "$Extend/$Usnjrnl:J",  # Old versions of acquire used $Usnjrnl:J
                ],
            )

            target.fs.mount(vol_name, vol)


class AcquireZipSubLoader(ZipSubLoader):
    """Loader for zip-based Acquire collections."""

    @staticmethod
    def detect(path: Path, zipfile: zf.Path) -> bool:
        return zipfile.joinpath(FILESYSTEMS_ROOT).exists() or zipfile.joinpath(FILESYSTEMS_LEGACY_ROOT).exists()

    def map(self, target: Target) -> None:
        path = self.zip
        if path.joinpath(FILESYSTEMS_ROOT).exists():
            path = path.joinpath(FILESYSTEMS_ROOT)
        find_and_map_dirs(target, path)
