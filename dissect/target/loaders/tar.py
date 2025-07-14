from __future__ import annotations

import logging
import tarfile as tf
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target import filesystem, target
from dissect.target.filesystems.tar import (
    TarFilesystemDirectoryEntry,
    TarFilesystemEntry,
)
from dissect.target.helpers import fsutil, loaderutil
from dissect.target.helpers.lazy import import_lazy
from dissect.target.loader import Loader, SubLoader

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

log = logging.getLogger(__name__)

TAR_EXT_COMP = (
    ".tar.gz",
    ".tar.xz",
    ".tar.bz",
    ".tar.bz2",
    ".tar.lzma",
    ".tar.lz",
    ".tgz",
    ".txz",
    ".tbz",
    ".tbz2",
    ".tlz",
    ".tlzma",
)
TAR_EXT = (".tar",)

TAR_MAGIC_COMP = (
    # gzip
    b"\x1f\x8b",
    # bzip2
    b"\x42\x5a\x68",
    # xz
    b"\xfd\x37\x7a\x58\x5a\x00",
    # lzma
    b"\x5d\x00\x00\x01\x00",
    b"\x5d\x00\x00\x10\x00",
    b"\x5d\x00\x00\x08\x00",
    b"\x5d\x00\x00\x10\x00",
    b"\x5d\x00\x00\x20\x00",
    b"\x5d\x00\x00\x40\x00",
    b"\x5d\x00\x00\x80\x00",
    b"\x5d\x00\x00\x00\x01",
    b"\x5d\x00\x00\x00\x02",
)
TAR_MAGIC = (tf.GNU_MAGIC, tf.POSIX_MAGIC)

WINDOWS_MEMBERS = (
    "windows/system32",
    "/windows/system32",
    "winnt",
    "/winnt",
)


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
    """Generic tar sub loader."""

    @staticmethod
    def detect(tarfile: tf.TarFile) -> bool:
        return True

    def map(self, target: target.Target) -> None:
        volumes = {}
        windows_found = False

        for member in self.tar.getmembers():
            if member.name == ".":
                continue

            if member.name.lower().startswith(WINDOWS_MEMBERS):
                windows_found = True
                if "/" in volumes:
                    # Root filesystem was already added
                    volumes["/"].case_sensitive = False

            if "/" not in volumes:
                vol = filesystem.VirtualFilesystem(case_sensitive=not windows_found)
                vol.tar = self.tar
                volumes["/"] = vol
                target.filesystems.add(vol)

            volume = volumes["/"]
            mname = member.name

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


class TarLoader(Loader):
    """Load tar files."""

    __subloaders__ = (
        import_lazy("dissect.target.loaders.containerimage").ContainerImageTarSubLoader,
        import_lazy("dissect.target.loaders.acquire").AcquireTarSubLoader,
        GenericTarSubLoader,  # should be last
    )

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)

        if is_compressed(path):
            log.warning(
                "Tar file %r is compressed, which will affect performance. "
                "Consider uncompressing the archive before passing the tar file to Dissect.",
                path,
            )

        self.fh = path.open("rb")
        self.tar = tf.open(mode="r:*", fileobj=self.fh)  # noqa: SIM115
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
        # The minimum file size of an uncompressed tar is 512 bytes, but a compressed tar file could be smaller.
        fh.seek(0)
        buf = fh.read(tf.BLOCKSIZE)
        headers = [buf[0:6]]
        if len(buf) >= 265:
            headers.append(buf[257 : 257 + 8])

        for header in headers:
            if header.startswith(magics):
                # We could be dealing with a compressed file that is not actually a tar.
                # To weed out a false positive we try to decompress and read ustar from
                # the first 512 bytes (or less) of the file.
                try:
                    tf.open(mode="r:*", fileobj=BytesIO(buf))  # noqa: SIM115
                except (tf.ReadError, tf.CompressionError, ValueError, EOFError):
                    continue
                return True
    return False


def is_compressed(path: Path) -> bool:
    return path.name.lower().endswith(TAR_EXT_COMP) or is_tar_magic(path, TAR_MAGIC_COMP)
