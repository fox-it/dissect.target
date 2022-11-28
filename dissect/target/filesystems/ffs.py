import struct

from dissect.ffs import c_ffs, ffs

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class FfsFilesystem(Filesystem):
    __fstype__ = "ffs"

    def __init__(self, fh, *args, **kwargs):
        self.ffs = ffs.FFS(fh)
        super().__init__(fh, *args, **kwargs)

    @staticmethod
    def detect(fh):
        try:
            offset = fh.tell()
            for sb_offset in ffs.SBLOCKSEARCH:
                fh.seek(sb_offset)
                block = fh.read(4096)
                magic = struct.unpack("<I", block[1372:1376])[0]

                if magic in (c_ffs.c_ffs.FS_UFS1_MAGIC, c_ffs.c_ffs.FS_UFS2_MAGIC):
                    fh.seek(offset)
                    return True

            fh.seek(offset)
            return False
        except Exception:
            return False

    def get(self, path):
        return FfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path, node=None):
        try:
            return self.ffs.get(path, node)
        except ffs.FileNotFoundError as e:
            raise FileNotFoundError(path, cause=e)
        except ffs.NotADirectoryError as e:
            raise NotADirectoryError(path, cause=e)
        except ffs.NotASymlinkError as e:
            raise NotASymlinkError(path, cause=e)
        except ffs.Error as e:
            raise FileNotFoundError(path, cause=e)


class FfsFilesystemEntry(FilesystemEntry):
    def _resolve(self):
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def get(self, path):
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_node(path, self.entry)
        return FfsFilesystemEntry(self.fs, entry_path, entry)

    def open(self):
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self):
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            for entry in self.readlink_ext().iterdir():
                yield entry
        else:
            for entry in self.entry.iterdir():
                if entry.name in (".", ".."):
                    continue

                yield entry

    def iterdir(self):
        for entry in self._iterdir():
            yield entry.name

    def scandir(self):
        for entry in self._iterdir():
            entry_path = fsutil.join(self.path, entry.name, alt_separator=self.fs.alt_separator)
            yield FfsFilesystemEntry(self.fs, entry_path, entry)

    def is_dir(self):
        try:
            return self._resolve().entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self):
        try:
            return self._resolve().entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self):
        return self.entry.is_symlink()

    def readlink(self):
        if not self.is_symlink():
            raise NotASymlinkError()

        return self.entry.link

    def stat(self):
        return self._resolve().lstat()

    def lstat(self):
        node = self.entry.inode

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = st_info = fsutil.stat_result(
            [
                self.entry.mode,
                self.entry.inum,
                0,
                node.di_nlink,
                node.di_uid,
                node.di_gid,
                node.di_size,
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

        # FFS2 has a birth time, FFS1 does not
        if btime := self.entry.btime:
            st_info.st_birthtime = btime.timestamp()

        return st_info
