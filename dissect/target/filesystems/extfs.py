import stat
from typing import Any, BinaryIO, Iterator, Optional

from dissect.extfs import extfs

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class ExtFilesystem(Filesystem):
    __type__ = "ext"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.extfs = extfs.ExtFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        fh.seek(1024)
        return fh.read(512)[56:58] == b"\x53\xef"

    def get(self, path: str) -> FilesystemEntry:
        return ExtFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: Optional[extfs.INode] = None) -> extfs.INode:
        try:
            return self.extfs.get(path, node)
        except extfs.FileNotFoundError as e:
            raise FileNotFoundError(path, cause=e)
        except extfs.NotADirectoryError as e:
            raise NotADirectoryError(path, cause=e)
        except extfs.NotASymlinkError as e:
            raise NotASymlinkError(path, cause=e)
        except extfs.Error as e:
            raise FileNotFoundError(path, cause=e)


class ExtFilesystemEntry(FilesystemEntry):
    def get(self, path: str) -> FilesystemEntry:
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return ExtFilesystemEntry(self.fs, full_path, self.fs._get_node(path, self.entry))

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
            for fname, f in self.entry.listdir().items():
                if fname in (".", ".."):
                    continue

                path = fsutil.join(self.path, fname, alt_separator=self.fs.alt_separator)
                yield ExtFilesystemEntry(self.fs, path, f)

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
        if not self.is_symlink():
            raise NotASymlinkError()

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        node = self.entry.inode

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                node.i_mode,
                self.entry.inum,
                id(self.fs),
                node.i_links_count,
                node.i_uid,
                node.i_gid,
                self.entry.size,
                # timestamp() returns a float which will fill both the integer and float fields
                self.entry.atime.timestamp(),
                self.entry.mtime.timestamp(),
                self.entry.ctime.timestamp(),
            ]
        )

        # Set the nanosecond resolution separately
        st_info.st_atime_ns = self.entry.atime_ns
        st_info.st_mtime_ns = self.entry.mtime_ns
        st_info.st_ctime_ns = self.entry.ctime_ns

        return st_info

    def attr(self) -> Any:
        return self._resolve().entry.xattr

    def lattr(self) -> Any:
        return self.entry.xattr
