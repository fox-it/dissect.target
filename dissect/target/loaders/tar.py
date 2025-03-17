from __future__ import annotations

import logging
import re
import tarfile as tf
from pathlib import Path
from typing import Iterable

from dissect.target import filesystem, target
from dissect.target.filesystems.tar import (
    TarFilesystemDirectoryEntry,
    TarFilesystemEntry,
)
from dissect.target.helpers import fsutil, loaderutil
from dissect.target.helpers.lazy import import_lazy
from dissect.target.loader import Loader, SubLoader

ContainerImageTarSubLoader: TarSubLoader = import_lazy(
    "dissect.target.loaders.containerimage"
).ContainerImageTarSubLoader
GenericTarSubLoader: TarSubLoader = import_lazy("dissect.target.loaders.tar").GenericTarSubLoader

log = logging.getLogger(__name__)

TAR_EXT_COMP = (
    ".tar.gz",
    ".tar.xz",
    ".tar.bz",
    ".tar.bz2",
    ".tgz",
    ".txz",
    ".tbz",
    ".tbz2",
)
TAR_EXT = (".tar",)

TAR_MAGIC_COMP = (
    # gzip
    b"\x1f\x8b",
    # bzip2
    b"\x42\x5A\x68",
    # xz
    b"\xfd\x37\x7a\x58\x5a\x00",
)
TAR_MAGIC = (tf.GNU_MAGIC, tf.POSIX_MAGIC)

ANON_FS_RE = re.compile(r"^fs[0-9]+$")


class TarLoader(Loader):
    """Load tar files."""

    __subloaders__ = [
        ContainerImageTarSubLoader,
        GenericTarSubLoader,  # should be last
    ]

    def __init__(self, path: Path | str, **kwargs):
        super().__init__(path)

        if isinstance(path, str):
            path = Path(path)

        if is_compressed(path):
            log.warning(
                f"Tar file {path!r} is compressed, which will affect performance. "
                "Consider uncompressing the archive before passing the tar file to Dissect."
            )

        self.fh = path.open("rb")
        self.tar = tf.open(mode="r:*", fileobj=self.fh)
        self.subloader = None

    @staticmethod
    def detect(path: Path) -> bool:
        return path.name.lower().endswith(TAR_EXT + TAR_EXT_COMP) or is_tar_magic(path, TAR_MAGIC + TAR_MAGIC_COMP)

    def map(self, target: target.Target) -> None:
        for candidate in self.__subloaders__:
            if candidate.detect(self.tar):
                self.subloader = candidate(self.tar)
                self.subloader.map(target)
                break


def is_tar_magic(path: Path, magics: Iterable[bytes]) -> bool:
    if not path.is_file():
        return False

    with path.open("rb") as fh:
        headers = [fh.read(6)]
        fh.seek(257)
        headers.append(fh.read(8))
        for header in headers:
            if header.startswith(magics):
                return True
    return False


def is_compressed(path: Path) -> bool:
    return path.name.lower().endswith(TAR_EXT_COMP) or is_tar_magic(path, TAR_MAGIC_COMP)


class TarSubLoader(SubLoader[tf.TarFile]):
    """Tar implementation of a :class:`SubLoader`."""

    def __init__(self, tar: tf.TarFile, *args, **kwargs):
        super().__init__(tar, *args, **kwargs)
        self.tar = tar

    @staticmethod
    def detect(tarfile: tf.TarFile) -> bool:
        """Only to be called internally by :class:`TarLoader`."""
        raise NotImplementedError

    def map(self, target: target.Target) -> None:
        """Only to be called internally by :class:`TarLoader`."""
        raise NotImplementedError


class GenericTarSubLoader(TarSubLoader):
    """Generic tar sub loader.

    Recognises acquire tar files and regular tar files. Attempts to map sysvol and c: volume names.
    """

    @staticmethod
    def detect(tarfile: tf.TarFile) -> bool:
        return True

    def map(self, target: target.Target) -> None:
        volumes = {}

        for member in self.tar.getmembers():
            if member.name == ".":
                continue

            if not member.name.startswith(("/fs/", "fs/", "/sysvol/", "sysvol/")):
                # Not an acquire tar
                if "/" not in volumes:
                    vol = filesystem.VirtualFilesystem(case_sensitive=True)
                    vol.tar = self.tar
                    volumes["/"] = vol
                    target.filesystems.add(vol)

                volume = volumes["/"]
                mname = member.name
            else:
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
