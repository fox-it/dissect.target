import stat
from typing import BinaryIO, Iterator, Optional

from dissect.squashfs import INode, SquashFS, c_squashfs, exceptions

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class SquashFSFilesystem(Filesystem):
    __fstype__ = "squashfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.squashfs = SquashFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return int.from_bytes(fh.read(4), "little") == c_squashfs.c_squashfs.SQUASHFS_MAGIC

    def get(self, path: str) -> FilesystemEntry:
        return SquashFSFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: Optional[INode] = None) -> INode:
        try:
            return self.squashfs.get(path, node)
        except exceptions.FileNotFoundError as e:
            raise FileNotFoundError(path, cause=e)
        except exceptions.NotADirectoryError as e:
            raise NotADirectoryError(path, cause=e)
        except exceptions.NotASymlinkError as e:
            raise NotASymlinkError(path, cause=e)
        except exceptions.Error as e:
            raise FileNotFoundError(path, cause=e)


class SquashFSFilesystemEntry(FilesystemEntry):
    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_node(path, self.entry)
        return SquashFSFilesystemEntry(self.fs, entry_path, entry)

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
                if entry.name in (".", ".."):
                    continue

                yield entry

    def iterdir(self) -> Iterator[str]:
        for entry in self._iterdir():
            yield entry.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        for entry in self._iterdir():
            entry_path = fsutil.join(self.path, entry.name, alt_separator=self.fs.alt_separator)
            yield SquashFSFilesystemEntry(self.fs, entry_path, entry)

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
            raise NotASymlinkError()

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        node = self.entry

        st_info = fsutil.stat_result(
            [
                node.mode,
                node.inode_number,
                id(self.fs),
                getattr(node.header, "nlink", 0),
                node.uid,
                node.gid,
                node.size,
                0,  # atime
                node.mtime.timestamp(),
                0,  # ctime
            ]
        )

        return st_info
