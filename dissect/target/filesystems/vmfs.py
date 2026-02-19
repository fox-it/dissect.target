from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import dissect.vmfs as vmfs
from dissect.vmfs.c_vmfs import c_vmfs

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import DirEntry, Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator


class VmfsFilesystem(Filesystem):
    __type__ = "vmfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.vmfs = vmfs.VMFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a VMFS filesystem on a given file-like object."""
        fh.seek(c_vmfs.FS3_FS_HEADER_OFFSET)
        sector = fh.read(512)
        return int.from_bytes(sector[:4], "little") in (
            c_vmfs.VMFS_MAGIC_NUMBER,
            c_vmfs.VMFSL_MAGIC_NUMBER,
        )

    def get(self, path: str) -> FilesystemEntry:
        return VmfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: vmfs.FileDescriptor | None = None) -> vmfs.FileDescriptor:
        """Returns an internal VMFS entry for a given path and optional relative entry."""
        try:
            return self.vmfs.get(path, node)
        except vmfs.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except vmfs.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except vmfs.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except vmfs.Error as e:
            raise FileNotFoundError(path) from e


class VmfsDirEntry(DirEntry):
    fs: VmfsFilesystem
    entry: vmfs.DirEntry

    def get(self) -> VmfsFilesystemEntry:
        return VmfsFilesystemEntry(self.fs, self.path, self.entry.file_descriptor)

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        if follow_symlinks and self.is_symlink():
            return super().is_dir(follow_symlinks=follow_symlinks)

        return self.entry.type == c_vmfs.FS3_DescriptorType.DIRECTORY

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        if follow_symlinks and self.is_symlink():
            return super().is_file(follow_symlinks=follow_symlinks)

        return self.entry.type == c_vmfs.FS3_DescriptorType.REGFILE

    def is_symlink(self) -> bool:
        return self.entry.type == c_vmfs.FS3_DescriptorType.SYMLINK

    def stat(self, *, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class VmfsFilesystemEntry(FilesystemEntry):
    fs: VmfsFilesystem
    entry: vmfs.FileDescriptor

    def get(self, path: str) -> FilesystemEntry:
        """Get a filesystem entry relative from the current one."""
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return VmfsFilesystemEntry(self.fs, full_path, self.fs._get_node(path, self.entry))

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def scandir(self) -> Iterator[VmfsDirEntry]:
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self._resolve().entry.iterdir():
            if entry.name in (".", ".."):
                continue

            yield VmfsDirEntry(self.fs, self.path, entry.name, entry)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a directory."""
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a file."""
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return self.entry.is_symlink()

    def readlink(self) -> str:
        """Read the link of the given path if it is a symlink. Returns a string."""
        if not self.is_symlink():
            raise NotASymlinkError

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        meta = self.entry.metadata

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = [
            self.entry.mode,
            self.entry.address,
            id(self.fs),
            meta.linkCount,
            meta.uid,
            meta.gid,
            self.entry.size,
            meta.atime,
            meta.mtime,
            meta.ctime,
        ]

        return fsutil.stat_result(st_info)
