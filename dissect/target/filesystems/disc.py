from __future__ import annotations

from typing import BinaryIO, Iterator

from dissect.disc import disc
import dissect.disc.exceptions as disc_exceptions
from dissect.disc.iso.c_iso_9660 import c_iso
from dissect.disc.udf.c_udf import UDF_MAGICS
from dissect.util.ts import to_unix

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class DiscFilesystem(Filesystem):
    __type__ = "disc"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.fs = disc.DISC(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        fh.seek(c_iso.SYSTEM_AREA_SIZE + 1)  # First byte of the first volume descriptor is reserved for the type
        magic = fh.read(5)

        return magic == b"CD001" or magic in UDF_MAGICS

    def get(self, path: str) -> DiscFilesystemEntry:
        try:
            return DiscFilesystemEntry(self, path, self.fs.get(path))
        except disc_exceptions.FileNotFoundError:
            raise FileNotFoundError(path)


class DiscFilesystemEntry(FilesystemEntry):
    def get(self, path: str) -> DiscFilesystemEntry:
        absolute_path = fsutil.join(self.path, path)
        try:
            return DiscFilesystemEntry(self.fs, absolute_path, self.entry.get(path))
        except disc_exceptions.FileNotFoundError:
            raise FileNotFoundError(absolute_path)

    def open(self) -> BinaryIO:
        if not self.is_file():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)
        if self.is_symlink():
            yield from self.readlink_ext().iterdir()
        else:
            for entry in self.entry.iterdir():
                if entry.name in [".", ".."]:
                    continue
                yield entry.name

    def scandir(self) -> Iterator[DiscFilesystemEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().scandir()
        else:
            for entry in self.entry.iterdir():
                if entry.name in [".", ".."]:
                    continue
                path = fsutil.join(self.path, entry.name)
                yield DiscFilesystemEntry(self.fs, path, entry)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        # Return whether this filesystem entry is a file
        try:
            return not self._resolve(follow_symlinks=follow_symlinks).entry.is_dir
        except FilesystemError:
            return False

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        # Return whether this filesystem entry is a directory
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        """Return whether this filesystem entry is a symlink."""
        return self.entry.is_symlink()

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError()
        return self.entry.readlink()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                self.entry.mode,
                self.entry.inode,
                id(self.fs),
                self.entry.nlinks,
                self.entry.uid,
                self.entry.gid,
                self.entry.size,
                to_unix(self.entry.atime),
                to_unix(self.entry.mtime),
                to_unix(self.entry.ctime),
            ]
        )
        return st_info
