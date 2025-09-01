from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.cramfs import CramFS, INode, c_cramfs, exception

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


class CramFSFilesystem(Filesystem):
    __type__ = "cramfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.cramfs = CramFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return int.from_bytes(fh.read(4), "little") == c_cramfs.c_cramfs.CRAMFS_MAGIC

    def get(self, path: str) -> FilesystemEntry:
        return CramFSFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: INode | None = None) -> INode:
        try:
            return self.cramfs.get(path, node)
        except exception.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except exception.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except exception.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except exception.Error as e:
            raise FileNotFoundError(path) from e


class CramFSFilesystemEntry(FilesystemEntry):
    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_node(path, self.entry)
        return CramFSFilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self) -> Iterator[INode]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            for entry in self.readlink_ext().iterdir():
                yield entry
        else:
            for entry in self.entry.iterdir():
                yield entry

    def iterdir(self) -> Iterator[str]:
        for entry in self._iterdir():
            yield entry.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        for entry in self._iterdir():
            entry_path = fsutil.join(self.path, entry.name, alt_separator=self.fs.alt_separator)
            yield CramFSFilesystemEntry(self.fs, entry_path, entry)

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
            raise NotASymlinkError

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        node = self.entry

        return fsutil.stat_result(
            [
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
                c_cramfs.c_cramfs.CRAMFS_BLOCK_SIZE,
                node.numblocks,
            ]
        )
