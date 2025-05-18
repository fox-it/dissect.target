from __future__ import annotations

import math
from typing import TYPE_CHECKING, BinaryIO

import dissect.btrfs as btrfs
from dissect.btrfs.c_btrfs import c_btrfs

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


class BtrfsFilesystem(Filesystem):
    __type__ = "btrfs"
    __multi_volume__ = True

    def __init__(self, fh: BinaryIO | list[BinaryIO], *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.btrfs = btrfs.Btrfs(fh)
        self.subfs = self.open_subvolume()
        self.subvolume = self.subfs.subvolume

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        fh.seek(c_btrfs.BTRFS_SUPER_INFO_OFFSET)
        block = fh.read(4096)
        magic = int.from_bytes(block[64:72], "little")

        return magic == c_btrfs.BTRFS_MAGIC

    @staticmethod
    def _detect_id(fh: BinaryIO) -> bytes | None:
        # First field is csum, followed by fsid
        fh.seek(c_btrfs.BTRFS_SUPER_INFO_OFFSET + c_btrfs.BTRFS_CSUM_SIZE)
        return fh.read(c_btrfs.BTRFS_FSID_SIZE)

    def iter_subfs(self) -> Iterator[BtrfsSubvolumeFilesystem]:
        for subvol in self.btrfs.subvolumes():
            if subvol.objectid == self.subfs.subvolume.objectid:
                # Skip the default volume as it's already opened by the main filesystem
                continue
            yield self.open_subvolume(subvolid=subvol.objectid)

    def open_subvolume(self, subvol: str | None = None, subvolid: int | None = None) -> BtrfsSubvolumeFilesystem:
        return BtrfsSubvolumeFilesystem(self, subvol, subvolid)

    def get(self, path: str) -> FilesystemEntry:
        return self.subfs.get(path)


class BtrfsSubvolumeFilesystem(Filesystem):
    __type__ = "btrfs"

    def __init__(self, fs: BtrfsFilesystem, subvol: str | None = None, subvolid: int | None = None):
        super().__init__(fs.volume, alt_separator=fs.alt_separator, case_sensitive=fs.case_sensitive)
        if subvol is not None and subvolid is not None:
            raise ValueError("Only one of subvol or subvolid is allowed")

        self.fs = fs
        self.btrfs = fs.btrfs
        if subvol:
            self.subvolume = self.btrfs.find_subvolume(subvol)
        elif subvolid:
            self.subvolume = self.btrfs.open_subvolume(subvolid)
        else:
            self.subvolume = self.btrfs.default_subvolume

    def get(self, path: str) -> FilesystemEntry:
        return BtrfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: btrfs.INode | None = None) -> btrfs.INode:
        try:
            return self.subvolume.get(path, node)
        except btrfs.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except btrfs.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except btrfs.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except btrfs.Error as e:
            raise FileNotFoundError(path) from e


class BtrfsFilesystemEntry(FilesystemEntry):
    fs: BtrfsFilesystem
    entry: btrfs.INode

    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_node(path, self.entry)
        return BtrfsFilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self) -> Iterator[btrfs.INode]:
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
            yield BtrfsFilesystemEntry(self.fs, entry_path, entry)

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
        entry = self.entry
        node = self.entry.inode

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                entry.mode,
                entry.inum,
                0,
                node.nlink,
                entry.uid,
                entry.gid,
                entry.size,
                # timestamp() returns a float which will fill both the integer and float fields
                entry.atime.timestamp(),
                entry.mtime.timestamp(),
                entry.ctime.timestamp(),
            ]
        )

        # Set the nanosecond resolution separately
        st_info.st_atime_ns = entry.atime_ns
        st_info.st_mtime_ns = entry.mtime_ns
        st_info.st_ctime_ns = entry.ctime_ns

        # Btrfs has a birth time, called otime
        st_info.st_birthtime = entry.otime.timestamp()
        st_info.st_birthtime_ns = entry.otime_ns

        # Add block information of the filesystem
        st_info.st_blksize = entry.btrfs.sector_size

        st_info.st_blocks = 0
        if not self.is_dir():
            st_info.st_blocks = (st_info.st_blksize // 512) * math.ceil(st_info.st_size / st_info.st_blksize)

        return st_info
