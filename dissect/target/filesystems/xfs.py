import logging
import stat
from typing import Any, BinaryIO, Iterator, Optional

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

log = logging.getLogger(__name__)


class XfsFilesystem(Filesystem):
    __fstype__ = "xfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.xfs = xfs.XFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        sector = fh.read(512)
        return sector[:4] == b"XFSB"

    def get(self, path: str) -> FilesystemEntry:
        return XfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: Optional[xfs.INode] = None) -> xfs.INode:
        try:
            return self.xfs.get(path, node)
        except xfs.FileNotFoundError:
            raise FileNotFoundError(path)
        except xfs.NotADirectoryError:
            raise NotADirectoryError(path)
        except xfs.NotASymlinkError:
            raise NotASymlinkError(path)
        except xfs.Error as e:
            raise FileNotFoundError(path, cause=e)


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
            for f in self.entry.listdir().keys():
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

        # XFS has a birth time, called crtime
        st_info.st_birthtime = self.entry.crtime.timestamp()

        return st_info

    def attr(self) -> Any:
        return self._resolve().entry.xattr

    def lattr(self) -> Any:
        return self.entry.xattr
