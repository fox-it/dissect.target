from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

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

if TYPE_CHECKING:
    from collections.abc import Iterator


class FfsFilesystem(Filesystem):
    __type__ = "ffs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.ffs = ffs.FFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        for sb_offset in ffs.SBLOCKSEARCH:
            fh.seek(sb_offset)
            block = fh.read(4096)
            magic = int.from_bytes(block[1372:1376], "little")

            if magic in (c_ffs.c_ffs.FS_UFS1_MAGIC, c_ffs.c_ffs.FS_UFS2_MAGIC):
                return True

        return False

    def get(self, path: str) -> FilesystemEntry:
        return FfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: ffs.INode | None = None) -> ffs.INode:
        try:
            return self.ffs.get(path, node)
        except ffs.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except ffs.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except ffs.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except ffs.Error as e:
            raise FileNotFoundError(path) from e


class FfsFilesystemEntry(FilesystemEntry):
    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_node(path, self.entry)
        return FfsFilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self) -> Iterator[ffs.INode]:
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
            yield FfsFilesystemEntry(self.fs, entry_path, entry)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.is_symlink()

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        node = self.entry.inode

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = st_info = fsutil.stat_result(
            [
                self.entry.mode,
                self.entry.inum,
                id(self.fs),
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

        # Note: stat on linux always returns the default block size of 4096
        # We are returning the actual block size of the filesystem, as on BSD
        st_info.st_blksize = self.fs.ffs.block_size
        # Note: st_blocks * 512 can be lower than st_blksize because FFS employs fragments
        st_info.st_blocks = self.entry.nblocks

        # Set the nanosecond resolution separately
        st_info.st_atime_ns = self.entry.atime_ns
        st_info.st_mtime_ns = self.entry.mtime_ns
        st_info.st_ctime_ns = self.entry.ctime_ns

        # FFS2 has a birth time, FFS1 does not
        if btime := self.entry.btime:
            st_info.st_birthtime = btime.timestamp()
            st_info.st_birthtime_ns = self.entry.btime_ns

        return st_info
