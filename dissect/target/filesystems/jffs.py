from typing import BinaryIO, Iterator, Optional

from dissect.jffs import c_jffs2, jffs2

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class JFFSFilesystem(Filesystem):
    __fstype__ = "jffs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.jffs2 = jffs2.JFFS2(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        block = fh.read(2)
        magic = int.from_bytes(block[0:2], "little")

        return magic in (
            c_jffs2.c_jffs2.JFFS2_MAGIC_BITMASK,
            c_jffs2.c_jffs2.JFFS2_OLD_MAGIC_BITMASK,
        )

    def get(self, path: str) -> FilesystemEntry:
        return JFFSFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: Optional[jffs2.INode] = None):
        try:
            return self.jffs2.get(path, node)
        except jffs2.FileNotFoundError as e:
            raise FileNotFoundError(path, cause=e)
        except jffs2.NotADirectoryError as e:
            raise NotADirectoryError(path, cause=e)
        except jffs2.NotASymlinkError as e:
            raise NotASymlinkError(path, cause=e)
        except jffs2.Error as e:
            raise FileNotFoundError(path, cause=e)


class JFFSFilesystemEntry(FilesystemEntry):
    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_node(path, self.entry)
        return JFFSFilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            for name, entry in self.readlink_ext().iterdir():
                yield name
        else:
            for name, entry in self.entry.iterdir():
                yield name

    def scandir(self) -> Iterator[FilesystemEntry]:
        for name in self.iterdir():
            entry_path = fsutil.join(self.path, name, alt_separator=self.fs.alt_separator)
            entry = self.fs.get(entry_path)
            yield JFFSFilesystemEntry(self.fs, entry_path, entry)

    def is_dir(self, follow_symlinks: bool = False) -> bool:
        try:
            return self._resolve(follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = False) -> bool:
        try:
            return self._resolve(follow_symlinks).entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.is_symlink()

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError()

        return self.entry.link

    def stat(self, follow_symlinks: bool = False) -> fsutil.stat_result:
        return self._resolve(follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        node = self.entry.inode

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                self.entry.mode,
                self.entry.inum,
                id(self.fs),
                1, # TODO: properly calculate nlink in dissect.jffs
                node.uid,
                node.gid,
                node.isize,
                self.entry.atime.timestamp(),
                self.entry.mtime.timestamp(),
                self.entry.ctime.timestamp(),
            ]
        )

        return st_info
