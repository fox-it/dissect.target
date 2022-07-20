import stat

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


class XfsFilesystem(Filesystem):
    __fstype__ = "xfs"

    def __init__(self, fh, *args, **kwargs):
        self.xfs = xfs.XFS(fh)
        super().__init__(fh, *args, **kwargs)

    @staticmethod
    def detect(fh):
        try:
            offset = fh.tell()
            fh.seek(0)
            sector = fh.read(512)
            fh.seek(offset)

            return sector[:4] == b"XFSB"
        except Exception:  # noqa
            return False

    def get(self, path):
        return XfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path, node=None):
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
    def _resolve(self):
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def get(self, path):
        return XfsFilesystemEntry(self.fs, fsutil.join(self.path, path), self.fs._get_node(path, self.entry))

    def open(self):
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def iterdir(self):
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

    def scandir(self):
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
                yield XfsFilesystemEntry(self.fs, fsutil.join(self.path, filename), f)

    def is_dir(self):
        try:
            return self._resolve().entry.filetype == stat.S_IFDIR
        except FilesystemError:
            return False

    def is_file(self):
        try:
            return self._resolve().entry.filetype == stat.S_IFREG
        except FilesystemError:
            return False

    def is_symlink(self):
        return self.entry.filetype == stat.S_IFLNK

    def readlink(self):
        return self.entry.link

    def stat(self):
        return self._resolve().lstat()

    def lstat(self):
        node = self.entry.inode

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                node.di_mode,
                self.entry.inum,
                0,
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

    def attr(self):
        return self._resolve().entry.xattr

    def lattr(self):
        return self.entry.xattr
