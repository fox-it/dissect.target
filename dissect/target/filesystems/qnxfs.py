from __future__ import annotations

from typing import BinaryIO, Iterator, Optional

import dissect.qnxfs as qnxfs
from dissect.qnxfs import qnx4, qnx6

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

INode = qnx4.INode | qnx6.INode


class QnxFilesystem(Filesystem):
    __type__ = "qnxfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.qnxfs = qnxfs.QNXFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        # Try QNX4
        fh.seek(qnxfs.c_qnx4.QNX4_BLOCK_SIZE)
        if fh.read(16) == b"/" + b"\x00" * 15:
            return True

        # Try QNX6
        for sb_offset in [qnxfs.c_qnx6.QNX6_BOOTBLOCK_SIZE, 0]:
            fh.seek(sb_offset)
            block = fh.read(qnxfs.c_qnx6.QNX6_SUPERBLOCK_SIZE)

            magics = [int.from_bytes(block[0:4], endian) for endian in ["little", "big"]]
            if qnxfs.c_qnx6.QNX6_SUPER_MAGIC in magics:
                return True

        return False

    def get(self, path: str) -> FilesystemEntry:
        return QnxFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: Optional[INode] = None) -> INode:
        try:
            return self.qnxfs.get(path, node)
        except qnxfs.FileNotFoundError as e:
            raise FileNotFoundError(path, cause=e)
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
        entry = self.fs._get_node(path, self.entry)
        return QnxFilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self) -> Iterator[tuple[str, INode]]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            for entry in self.readlink_ext().iterdir():
                yield entry
        else:
            for name, entry in self.entry.iterdir():
                if name in (".", ".."):
                    continue

                yield name, entry

    def iterdir(self) -> Iterator[str]:
        for name, _ in self._iterdir():
            yield name

    def scandir(self) -> Iterator[FilesystemEntry]:
        for name, entry in self._iterdir():
            entry_path = fsutil.join(self.path, name, alt_separator=self.fs.alt_separator)
            yield QnxFilesystemEntry(self.fs, entry_path, entry)

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
            raise NotASymlinkError()

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = st_info = fsutil.stat_result(
            [
                self.entry.mode,
                self.entry.inum,
                id(self.fs),
                getattr(self.entry, "nlink", 1),  # Only QNX4 has nlink
                self.entry.uid,
                self.entry.gid,
                self.entry.size,
                # timestamp() returns a float which will fill both the integer and float fields
                self.entry.atime.timestamp(),
                self.entry.mtime.timestamp(),
                self.entry.ctime.timestamp(),
            ]
        )

        # QNX also have an ftime but unsure what it is

        return st_info
