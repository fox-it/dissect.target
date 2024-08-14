import os
from pathlib import Path
from typing import BinaryIO, Iterator
from urllib.parse import unquote

from dissect.target.exceptions import (
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import (
    Filesystem,
    FilesystemEntry,
    VirtualDirectory,
    VirtualFilesystem,
)
from dissect.target.helpers import fsutil


class DirectoryFilesystem(Filesystem):
    __type__ = "dir"

    def __init__(self, path: Path, unquote_path: bool = False, *args, **kwargs):
        super().__init__(None, *args, **kwargs)
        self.base_path = path

        self._fs = VirtualFilesystem(alt_separator=self.alt_separator, case_sensitive=self.case_sensitive)

        self.map_members(unquote_path)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.base_path}>"

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on DirectoryFilesystem class")

    def map_members(self, unquote_path: bool) -> None:
        """Map members of a path into the VFS."""

        for path in self.base_path.rglob("*"):
            pname = str(path)

            if not pname.startswith(str(self.base_path)) or pname == ".":
                continue

            rel_name = fsutil.normpath(pname[len(str(self.base_path)) :], alt_separator=self.alt_separator)

            if unquote_path:
                rel_name = unquote(rel_name)

            self._fs.map_file_entry(rel_name, DirectoryFilesystemEntry(self, rel_name, path))

    def get(self, path: str, relentry: FilesystemEntry = None) -> FilesystemEntry:
        """Returns a FilesystemEntry object corresponding to the given path."""
        return self._fs.get(path, relentry=relentry)


# Note: We subclass from VirtualDirectory because VirtualFilesystem is currently only compatible with VirtualDirectory
# Subclass from VirtualDirectory so we get that compatibility for free, and override the rest to do our own thing
class DirectoryFilesystemEntry(VirtualDirectory):
    fs: DirectoryFilesystem
    entry: Path

    def __init__(self, fs: DirectoryFilesystem, path: str, entry: Path):
        super().__init__(fs, path)
        self.entry = entry

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
            raise NotASymlinkError()

        # We want to get the "truest" form of the symlink
        # If we use the readlink() of pathlib.Path directly, it gets thrown into the path parsing of pathlib
        # Because DirectoryFilesystem may also be used with TargetPath, we specifically handle that case here
        # and use os.readlink for host paths
        if isinstance(self.entry, fsutil.TargetPath):
            return self.entry.get().readlink()
        else:
            return os.readlink(self.entry)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).entry.lstat()

    def lstat(self) -> fsutil.stat_result:
        return fsutil.stat_result.copy(self.entry.lstat())

    def attr(self) -> dict[str, bytes]:
        return fsutil.fs_attrs(self.entry, follow_symlinks=True)

    def lattr(self) -> dict[str, bytes]:
        return fsutil.fs_attrs(self.entry, follow_symlinks=False)
