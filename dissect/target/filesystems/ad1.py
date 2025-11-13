from __future__ import annotations

import stat
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence import ad1

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator


class AD1Filesystem(Filesystem):
    __type__ = "ad1"

    def __init__(self, fh: BinaryIO | list[BinaryIO], *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.ad1 = ad1.AD1(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return fh.read(16) == b"ADSEGMENTEDFILE\x00"

    def get(self, path: str) -> FilesystemEntry:
        return AD1FilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(self, path: str) -> ad1.FileEntry:
        try:
            return self.ad1.get(path)
        except ad1.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except ad1.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except ad1.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except ad1.Error as e:
            raise FileNotFoundError(path) from e


class AD1FilesystemEntry(FilesystemEntry):
    fs: AD1Filesystem
    entry: ad1.FileEntry

    def get(self, path: str) -> FilesystemEntry:
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return AD1FilesystemEntry(self.fs, full_path, self.fs._get_entry(full_path))

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.entry.open()

    def iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        yield from self.entry.listdir()

    def scandir(self) -> Iterator[FilesystemEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for file in self.entry.iterdir():
            path = fsutil.join(self.path, file.name, alt_separator=self.fs.alt_separator)
            yield AD1FilesystemEntry(self.fs, path, file)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.is_symlink()

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError(self.path)
        return self.entry.readlink()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        if self.is_symlink():
            mode = stat.S_IFLNK
        elif self.is_file():
            mode = stat.S_IFREG
        else:
            mode = stat.S_IFDIR

        st_info = fsutil.stat_result(
            [
                mode | 0o777,
                fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator),  # inum
                id(self.fs),
                1,  # nlink
                0,  # uid
                0,  # gid
                self.entry.size,
                self.entry.atime.timestamp(),
                self.entry.mtime.timestamp(),
                self.entry.ctime.timestamp(),
            ]
        )

        st_info.st_birthtime = self.entry.btime.timestamp()
        return st_info
