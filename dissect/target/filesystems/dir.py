import os
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class DirectoryFilesystem(Filesystem):
    __fstype__ = "dir"

    def __init__(self, path: Path, *args, **kwargs):
        super().__init__(None, *args, **kwargs)
        self.base_path = path

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.base_path}>"

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on DirectoryFilesystem class")

    def get(self, path: str) -> FilesystemEntry:
        path = path.strip("/")

        if not path:
            return DirectoryFilesystemEntry(self, "/", self.base_path)

        if not self.case_sensitive:
            searchpath = self.base_path

            for p in path.split("/"):
                match = [d for d in searchpath.iterdir() if d.name.lower() == p.lower()]

                if not match or len(match) > 1:
                    raise FileNotFoundError(path)

                searchpath = match[0]

            entry = searchpath
        else:
            entry = self.base_path.joinpath(path.strip("/"))

        try:
            entry.lstat()
            return DirectoryFilesystemEntry(self, path, entry)
        except Exception:
            raise FileNotFoundError(path)


class DirectoryFilesystemEntry(FilesystemEntry):
    def _resolve(self) -> FilesystemEntry:
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def get(self, path: str) -> FilesystemEntry:
        path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return self.fs.get(path)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open("rb")

    def iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().iterdir()
        else:
            for item in self.entry.iterdir():
                yield item.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().scandir()
        else:
            for item in self.entry.iterdir():
                path = fsutil.join(self.path, item.name, alt_separator=self.fs.alt_separator)
                yield DirectoryFilesystemEntry(self.fs, path, item)

    def exists(self) -> bool:
        try:
            return self._resolve().entry.exists()
        except FilesystemError:
            return False

    def is_dir(self) -> bool:
        try:
            return self._resolve().entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self) -> bool:
        try:
            return self._resolve().entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.is_symlink()

    def readlink(self) -> str:
        return os.readlink(self.entry)  # Python 3.7 compatibility

    def stat(self) -> fsutil.stat_result:
        return self._resolve().entry.lstat()

    def lstat(self) -> fsutil.stat_result:
        return fsutil.stat_result.copy(self.entry.lstat())

    def attr(self) -> Any:
        raise TypeError()

    def lattr(self) -> Any:
        raise TypeError()
