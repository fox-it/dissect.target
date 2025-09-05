from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import dissect.cramfs as cramfs
from dissect.cramfs.c_cramfs import c_cramfs

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

    from dissect.cramfs import INode


class CramFSFilesystem(Filesystem):
    __type__ = "cramfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.cramfs = cramfs.CramFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a CramFS filesystem on a given file-like object."""
        return int.from_bytes(fh.read(4), "little") == c_cramfs.CRAMFS_MAGIC

    def get(self, path: str) -> FilesystemEntry:
        return CramFSFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: INode | None = None) -> INode:
        """Returns an internal CramFS inode for a given path and optional relative inode."""
        try:
            return self.cramfs.get(path, node)
        except cramfs.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except cramfs.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except cramfs.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except cramfs.Error as e:
            raise FileNotFoundError(path) from e


class CramFSFilesystemEntry(FilesystemEntry):
    fs: CramFSFilesystem
    entry: INode

    def get(self, path: str) -> FilesystemEntry:
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return CramFSFilesystemEntry(self.fs, full_path, self.fs._get_node(path, self.entry))

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self) -> Iterator[INode]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().iterdir()
        else:
            yield from self.entry.iterdir()

    def iterdir(self) -> Iterator[str]:
        """List the directory contents of a directory. Returns a generator of strings."""
        yield from (inode.name for inode in self._iterdir())

    def scandir(self) -> Iterator[FilesystemEntry]:
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        yield from (self.get(entry.name) for entry in self._iterdir())

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
            raise NotASymlinkError

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        node = self.entry

        # mode, ino, dev, nlink, uid, gid, size, ..., blocksize, numblocks
        st_info = [
            node.mode,
            0,  # cramfs inodes don't have an inode number
            id(self.fs),  # device ID of the filesystem
            1,  # cramfs inodes always have 1 nlinks
            node.uid,
            node.gid,
            node.size,
            0,  # cramfs inodes don't have timestamps
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            c_cramfs.CRAMFS_BLOCK_SIZE,
            len(node.blocks),
        ]

        return fsutil.stat_result(st_info)
