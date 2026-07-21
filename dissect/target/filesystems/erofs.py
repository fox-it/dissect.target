from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import dissect.erofs as erofs

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import DirEntry, Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.erofs import INode


class EROFSFilesystem(Filesystem):
    __type__ = "erofs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.erofs = erofs.EROFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a EROFS filesystem on a given file-like object."""
        return erofs.EROFS.detect_erofs(fh)

    def get(self, path: str) -> FilesystemEntry:
        return EROFSFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: INode | None = None) -> INode:
        """Returns an internal EROFS inode for a given path and optional relative inode."""
        try:
            return self.erofs.get(path, node)
        except erofs.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except erofs.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except erofs.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except erofs.Error as e:
            raise FileNotFoundError(path) from e


class EROFSDirEntry(DirEntry):
    fs: EROFSFilesystem
    entry: INode

    def get(self) -> EROFSFilesystemEntry:
        return EROFSFilesystemEntry(self.fs, self.path, self.entry)

    def stat(self, *, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class EROFSFilesystemEntry(FilesystemEntry):
    fs: EROFSFilesystem
    entry: INode

    def get(self, path: str) -> FilesystemEntry:
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return EROFSFilesystemEntry(self.fs, full_path, self.fs._get_node(path, self.entry))

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def scandir(self) -> Iterator[EROFSDirEntry]:
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self._resolve().entry.iterdir():
            if entry.name in (".", ".."):
                continue

            yield EROFSDirEntry(self.fs, self.path, entry.name, entry)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a directory."""
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a file."""
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return self.entry.is_symlink()

    def readlink(self) -> str:
        """Read the link of the given path if it is a symlink. Returns a string."""
        if not self.is_symlink():
            raise NotASymlinkError(self.path)

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        node = self.entry

        # 64-byte inodes store an mtime and we could use the super block timestamp here, but we currently don't
        st_info = [
            node.mode,
            node.inode_number,
            id(self.fs),
            node.nlink,
            node.uid,
            node.gid,
            node.size,
            0,
            0,
            0,
        ]

        return fsutil.stat_result(st_info)
