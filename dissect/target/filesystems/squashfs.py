from __future__ import annotations

import stat
from typing import TYPE_CHECKING, BinaryIO

from dissect.squashfs import INode, SquashFS, c_squashfs, exceptions

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


class SquashFSFilesystem(Filesystem):
    __type__ = "squashfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.squashfs = SquashFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return int.from_bytes(fh.read(4), "little") == c_squashfs.c_squashfs.SQUASHFS_MAGIC

    def get(self, path: str) -> FilesystemEntry:
        return SquashFSFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: INode | None = None) -> INode:
        try:
            return self.squashfs.get(path, node)
        except exceptions.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except exceptions.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except exceptions.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except exceptions.Error as e:
            raise FileNotFoundError(path) from e


class SquashFSDirEntry(DirEntry):
    fs: SquashFSFilesystem
    entry: INode

    def get(self) -> SquashFSFilesystemEntry:
        return SquashFSFilesystemEntry(self.fs, self.path, self.entry)

    def stat(self, *, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class SquashFSFilesystemEntry(FilesystemEntry):
    fs: SquashFSFilesystem
    entry: INode

    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_node(path, self.entry)
        return SquashFSFilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def scandir(self) -> Iterator[SquashFSDirEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self._resolve().entry.iterdir():
            if entry.name in (".", ".."):
                continue

            yield SquashFSDirEntry(self.fs, self.path, entry.name, entry)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.type == stat.S_IFDIR
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.type == stat.S_IFREG
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.type == stat.S_IFLNK

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
                node.inode_number,
                id(self.fs),
                getattr(node.header, "nlink", 1),
                node.uid,
                node.gid,
                node.size,
                0,  # atime
                node.mtime.timestamp(),
                0,  # ctime
            ]
        )
