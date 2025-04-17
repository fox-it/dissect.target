from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO, Union

import dissect.qnxfs as qnxfs
from dissect.qnxfs.qnx4 import INode as INode4
from dissect.qnxfs.qnx6 import INode as INode6

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

INode = Union[INode4, INode6]


class QnxFilesystem(Filesystem):
    __type__ = "qnxfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.qnxfs = qnxfs.QNXFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return qnxfs.is_qnxfs(fh)

    def get(self, path: str) -> FilesystemEntry:
        return QnxFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: INode | None = None) -> INode:
        try:
            return self.qnxfs.get(path, node)
        except qnxfs.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except qnxfs.NotADirectoryError as e:
            raise NotADirectoryError(path, cause=e)
        except qnxfs.NotASymlinkError as e:
            raise NotASymlinkError(path, cause=e)
        except qnxfs.Error as e:
            raise FileNotFoundError(path, cause=e)


class QnxFilesystemEntry(FilesystemEntry):
    fs: QnxFilesystem
    entry: INode

    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return QnxFilesystemEntry(self.fs, entry_path, self.fs._get_node(path, self.entry))

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self) -> Iterator[tuple[str, INode]]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().iterdir()
        else:
            yield from self.entry.iterdir()

    def iterdir(self) -> Iterator[str]:
        yield from (name for name, _ in self._iterdir())

    def scandir(self) -> Iterator[FilesystemEntry]:
        for name, entry in self._iterdir():
            entry_path = fsutil.join(self.path, name, alt_separator=self.fs.alt_separator)
            yield QnxFilesystemEntry(self.fs, entry_path, entry)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks).entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.is_symlink()

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                self.entry.mode,
                self.entry.inum,
                id(self.fs),
                getattr(self.entry, "nlink", 1),  # Only QNX4 has nlink
                self.entry.uid,
                self.entry.gid,
                self.entry.size,
                self.entry.atime.timestamp(),
                self.entry.mtime.timestamp(),
                self.entry.ctime.timestamp(),
            ]
        )

        st_info.st_birthtime = self.entry.ftime.timestamp()

        st_info.st_blksize = self.fs.qnxfs.block_size
        # Blocks are always calculated based on 512 byte blocks
        # https://github.com/torvalds/linux/blob/c1e939a21eb111a6d6067b38e8e04b8809b64c4e/fs/qnx6/inode.c#L560-L561
        st_info.st_blocks = (self.entry.size + 511) >> 9

        return st_info
