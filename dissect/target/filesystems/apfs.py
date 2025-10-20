from __future__ import annotations

import math
from typing import TYPE_CHECKING, BinaryIO

import dissect.apfs as apfs

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import DirEntry, Filesystem, FilesystemEntry, VirtualFilesystem
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator
    from uuid import UUID

    from dissect.apfs.objects.fs import DirectoryEntry, INode


class ApfsFilesystem(Filesystem):
    __type__ = "apfs-container"

    def __init__(self, fh: BinaryIO | list[BinaryIO], *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.container = apfs.APFS(fh)
        self._volumes = [ApfsVolumeFilesystem(self, uuid=vol.uuid) for vol in self.container.volumes]

        self.vfs = VirtualFilesystem()

        for vol in self._volumes:
            self.vfs.map_file_entry(vol.volume.name, vol.get("/"))

    def __repr__(self) -> str:
        return f"<Filesystem type={self.__type__} volumes={len(self._volumes)}>"

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        block = fh.read(4096)
        return block[32:36] == b"NXSB"

    def iter_subfs(self) -> Iterator[ApfsVolumeFilesystem]:
        yield from self._volumes

    def get(self, path: str) -> FilesystemEntry:
        return self.vfs.get(path)


class ApfsVolumeFilesystem(Filesystem):
    __type__ = "apfs"

    def __init__(self, fs: ApfsFilesystem, name: str | None = None, uuid: UUID | None = None):
        if name is not None and uuid is not None:
            raise ValueError("Only one of name or uuid is allowed")

        self.container = fs

        if name:
            self.apfs = next((vol for vol in self.container.container.volumes if vol.name == name), None)
        elif uuid:
            self.apfs = next((vol for vol in self.container.container.volumes if vol.uuid == uuid), None)
        else:
            raise ValueError("Either name or uuid must be provided")

        super().__init__(fs.volume, alt_separator=fs.alt_separator, case_sensitive=not self.apfs.is_case_insensitive)

    def __repr__(self) -> str:
        return f"<Filesystem type={self.__type__} name={self.apfs.name} uuid={self.apfs.uuid}>"

    def get(self, path: str) -> FilesystemEntry:
        return ApfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: INode | None = None) -> INode:
        try:
            return self.apfs.get(path, node)
        except apfs.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except apfs.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except apfs.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except apfs.Error as e:
            raise FileNotFoundError(path) from e


class ApfsDirEntry(DirEntry):
    fs: ApfsVolumeFilesystem
    entry: DirectoryEntry

    def get(self) -> ApfsFilesystemEntry:
        return ApfsFilesystemEntry(self.fs, self.path, self.entry.inode)

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        if follow_symlinks and self.is_symlink():
            return super().is_dir(follow_symlinks=follow_symlinks)

        return self.entry.is_dir()

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        if follow_symlinks and self.is_symlink():
            return super().is_file(follow_symlinks=follow_symlinks)

        return self.entry.is_file()

    def is_symlink(self) -> bool:
        return self.entry.is_symlink()

    def stat(self, *, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class ApfsFilesystemEntry(FilesystemEntry):
    fs: ApfsVolumeFilesystem
    entry: INode

    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_node(path, self.entry)
        return ApfsFilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def scandir(self) -> Iterator[FilesystemEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self._resolve().entry.iterdir():
            if entry.name in (".", ".."):
                continue

            yield ApfsDirEntry(self.fs, self.path, entry.name, entry)

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
            raise NotASymlinkError(self.path)

        return self.entry.readlink()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        entry = self.entry
        node = self.entry.inode

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                entry.mode,
                entry.oid,
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
        st_info.st_atime_ns = entry.inode.access_time
        st_info.st_mtime_ns = entry.inode.mod_time
        st_info.st_ctime_ns = entry.inode.change_time

        st_info.st_birthtime = entry.btime.timestamp()
        st_info.st_birthtime_ns = entry.inode.create_time

        # Add block information of the filesystem
        st_info.st_blksize = self.fs.container.container.block_size

        st_info.st_blocks = 0
        if not self.is_dir():
            st_info.st_blocks = (st_info.st_blksize // 512) * math.ceil(st_info.st_size / st_info.st_blksize)

        return st_info
