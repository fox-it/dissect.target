from __future__ import annotations

import logging
import stat
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.xfs import xfs

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

log = logging.getLogger(__name__)


class XfsFilesystem(Filesystem):
    __type__ = "xfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.xfs = xfs.XFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        sector = fh.read(512)
        return sector[:4] == b"XFSB"

    def get(self, path: str) -> FilesystemEntry:
        return XfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: xfs.INode | None = None) -> xfs.INode:
        try:
            return self.xfs.get(path, node)
        except xfs.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except xfs.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except xfs.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except xfs.Error as e:
            raise FileNotFoundError(path) from e


class XfsFilesystemEntry(FilesystemEntry):
    def get(self, path: str) -> FilesystemEntry:
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return XfsFilesystemEntry(self.fs, full_path, self.fs._get_node(path, self.entry))

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            for f in self.readlink_ext().iterdir():
                yield f
        else:
            for f in self.entry.listdir():
                if f in (".", ".."):
                    continue
                yield f

    def scandir(self) -> Iterator[FilesystemEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            for f in self.readlink_ext().scandir():
                yield f
        else:
            for filename, f in self.entry.listdir().items():
                if filename in (".", ".."):
                    continue

                if filename is None:
                    continue
                path = fsutil.join(self.path, filename, alt_separator=self.fs.alt_separator)
                yield XfsFilesystemEntry(self.fs, path, f)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.filetype == stat.S_IFDIR
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.filetype == stat.S_IFREG
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.filetype == stat.S_IFLNK

    def readlink(self) -> str:
        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        node = self.entry.inode

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                node.di_mode,
                self.entry.inum,
                id(self.fs),
                node.di_nlink,
                node.di_uid,
                node.di_gid,
                self.entry.size,
                self.entry.atime.timestamp(),
                self.entry.mtime.timestamp(),
                self.entry.ctime.timestamp(),
            ]
        )

        # Set the nanosecond resolution separately
        st_info.st_atime_ns = self.entry.atime_ns
        st_info.st_mtime_ns = self.entry.mtime_ns
        st_info.st_ctime_ns = self.entry.ctime_ns

        st_info.st_blksize = self.fs.xfs.block_size
        # Convert number of filesystem blocks to basic blocks
        # Reference: https://github.com/torvalds/linux/blob/e32cde8d2bd7d251a8f9b434143977ddf13dcec6/fs/xfs/xfs_iops.c#L602 # noqa: E501
        # Note that block size in XFS is always a multiple of 512, so the division below is safe
        st_info.st_blocks = self.entry.nblocks * (self.fs.xfs.block_size // 512)

        # XFS has a birth time, since inode version 3 (version 5 of filesystem)
        st_info.st_birthtime = self.entry.crtime.timestamp()
        st_info.st_birthtime_ns = self.entry.crtime_ns

        return st_info

    def attr(self) -> Any:
        return self._resolve().entry.xattr

    def lattr(self) -> Any:
        return self.entry.xattr
