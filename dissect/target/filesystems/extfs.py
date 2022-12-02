import stat

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
    __fstype__ = "ext"

    def __init__(self, fh, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.extfs = extfs.ExtFS(fh)

    @staticmethod
    def detect(fh):
        try:
            offset = fh.tell()
            fh.seek(1024)
            sector = fh.read(512)
            fh.seek(offset)

            return sector[56:58] == b"\x53\xef"
        except Exception:  # noqa
            return False

    def get(self, path):
        return ExtFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path, node=None):
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
    def _resolve(self):
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def get(self, path):
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return ExtFilesystemEntry(self.fs, full_path, self.fs._get_node(path, self.entry))

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
            for fname, f in self.entry.listdir().items():
                if fname in (".", ".."):
                    continue

                path = fsutil.join(self.path, fname, alt_separator=self.fs.alt_separator)
                yield ExtFilesystemEntry(self.fs, path, f)

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
        if not self.is_symlink():
            raise NotASymlinkError()

        return self.entry.link

    def stat(self):
        return self._resolve().lstat()

    def lstat(self):
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

    def attr(self):
        return self._resolve().entry.xattr

    def lattr(self):
        return self.entry.xattr
