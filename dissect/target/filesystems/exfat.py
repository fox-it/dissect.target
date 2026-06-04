from __future__ import annotations

import math
import stat
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO

import dissect.fat as fat
from dissect.fat import exfat

from dissect.target.exceptions import FileNotFoundError, IsADirectoryError, NotADirectoryError
from dissect.target.filesystem import DirEntry, Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator


class ExFatFilesystem(Filesystem):
    __type__ = "exfat"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, case_sensitive=False, alt_separator="\\", **kwargs)
        self.exfat = exfat.ExFAT(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect an exFAT filesystem on a given file-like object."""
        try:
            exfat.validate_boot_sector(fh.read(512))
        except fat.InvalidBootSector:
            return False
        else:
            return True

    def get(self, path: str) -> FilesystemEntry:
        return ExFatFilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(
        self, path: str, entry: exfat.RootDirectory | exfat.DirectoryEntry | None = None
    ) -> exfat.RootDirectory | exfat.DirectoryEntry:
        """Returns an internal exFAT entry for a given path and optional relative entry."""
        try:
            return self.exfat.get(path, dirent=entry)
        except fat.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except fat.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except fat.Error as e:
            raise FileNotFoundError(path) from e

    @cached_property
    def serial(self) -> int | str | None:
        return int(self.exfat.volume_id, 16)


class ExFatDirEntry(DirEntry):
    fs: ExFatFilesystem
    entry: exfat.RootDirectory | exfat.DirectoryEntry

    def get(self) -> ExFatFilesystemEntry:
        return ExFatFilesystemEntry(self.fs, self.path, self.entry)

    def stat(self, *, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class ExFatFilesystemEntry(FilesystemEntry):
    fs: ExFatFilesystem
    entry: exfat.RootDirectory | exfat.DirectoryEntry

    def get(self, path: str) -> FilesystemEntry:
        """Get a filesystem entry relative from the current one."""
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return ExFatFilesystemEntry(self.fs, full_path, self.fs._get_entry(path, self.entry))

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.entry.open()

    def scandir(self) -> Iterator[FilesystemEntry]:
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self.entry.iterdir():
            if entry.name in (".", ".."):
                continue

            yield ExFatDirEntry(self.fs, self.path, entry.name, entry)

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return False

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a directory."""
        return self.entry.is_directory()

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a file."""
        return not self.is_dir()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                (stat.S_IFDIR if self.is_dir() else stat.S_IFREG) | 0o777,
                self.entry.cluster,
                id(self.fs),
                1,
                0,
                0,
                self.entry.size,
                self.entry.atime.timestamp(),
                self.entry.mtime.timestamp(),
                self.entry.ctime.timestamp(),
            ]
        )

        st_info.st_blocks = math.ceil(self.entry.size / self.entry.fs.cluster_size)
        st_info.st_blksize = self.entry.fs.cluster_size
        return st_info
