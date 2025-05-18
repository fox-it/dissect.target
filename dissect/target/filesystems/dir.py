from __future__ import annotations

import os
from typing import TYPE_CHECKING, BinaryIO

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
    from pathlib import Path


class DirectoryFilesystem(Filesystem):
    __type__ = "dir"

    def __init__(self, path: Path, *args, **kwargs):
        super().__init__(None, *args, **kwargs)
        self.base_path = path

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.base_path}>"

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on DirectoryFilesystem class")

    def _resolve_path(self, path: str) -> Path:
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

        return entry

    def get(self, path: str) -> FilesystemEntry:
        if not (path := path.strip("/")):
            return DirectoryFilesystemEntry(self, "/", self.base_path)

        entry = self._resolve_path(path)

        try:
            entry.lstat()
            return DirectoryFilesystemEntry(self, path, entry)
        except Exception:
            raise FileNotFoundError(path)


class DirectoryFilesystemEntry(FilesystemEntry):
    entry: Path

    def get(self, path: str) -> FilesystemEntry:
        path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return self.fs.get(path)

    def open(self) -> BinaryIO:
        try:
            if self.is_dir():
                raise IsADirectoryError(self.path)
            return self._resolve().entry.open("rb")
        except (PermissionError, OSError) as e:
            raise FilesystemError from e

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
        try:
            return self.entry.is_symlink()
        except (FilesystemError, OSError):
            return False

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError

        # We want to get the "truest" form of the symlink
        # If we use the readlink() of pathlib.Path directly, it gets thrown into the path parsing of pathlib
        # Because DirectoryFilesystem may also be used with TargetPath, we specifically handle that case here
        # and use os.readlink for host paths
        if isinstance(self.entry, fsutil.TargetPath):
            return self.entry.get().readlink()
        return os.readlink(self.entry)  # noqa: PTH115

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).entry.lstat()

    def lstat(self) -> fsutil.stat_result:
        return fsutil.stat_result.copy(self.entry.lstat())

    def attr(self) -> dict[str, bytes]:
        return fsutil.fs_attrs(self.entry, follow_symlinks=True)

    def lattr(self) -> dict[str, bytes]:
        return fsutil.fs_attrs(self.entry, follow_symlinks=False)
