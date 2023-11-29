from typing import BinaryIO, Iterator, Optional

import dissect.vmfs as vmfs
from dissect.vmfs.c_vmfs import c_vmfs
from dissect.vmfs.vmfs import FileDescriptor

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class VmfsFilesystem(Filesystem):
    __type__ = "vmfs"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.vmfs = vmfs.VMFS(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a VMFS filesystem on a given file-like object."""
        fh.seek(c_vmfs.VMFS_FS3_BASE)
        sector = fh.read(512)
        return int.from_bytes(sector[:4], "little") in (
            c_vmfs.VMFS_FS3_MAGIC,
            c_vmfs.VMFSL_FS3_MAGIC,
        )

    def get(self, path: str) -> FilesystemEntry:
        """Returns a VmfsFilesystemEntry object corresponding to the given pathname"""
        return VmfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: Optional[FileDescriptor] = None) -> FileDescriptor:
        """Returns an internal VMFS entry for a given path and optional relative entry."""
        try:
            return self.vmfs.get(path, node)
        except vmfs.FileNotFoundError as e:
            raise FileNotFoundError(path, cause=e)
        except vmfs.NotADirectoryError as e:
            raise NotADirectoryError(path, cause=e)
        except vmfs.NotASymlinkError as e:
            raise NotASymlinkError(path, cause=e)
        except vmfs.Error as e:
            raise FileNotFoundError(path, cause=e)


class VmfsFilesystemEntry(FilesystemEntry):
    def get(self, path: str) -> FilesystemEntry:
        """Get a filesystem entry relative from the current one."""
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return VmfsFilesystemEntry(self.fs, full_path, self.fs._get_node(path, self.entry))

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self) -> Iterator[FileDescriptor]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            for f in self.readlink_ext().iterdir():
                yield f
        else:
            for f in self.entry.iterdir():
                if f.name in (".", ".."):
                    continue

                yield f

    def iterdir(self) -> Iterator[str]:
        """List the directory contents of a directory. Returns a generator of strings."""
        for f in self._iterdir():
            yield f.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        for f in self._iterdir():
            path = fsutil.join(self.path, f.name, alt_separator=self.fs.alt_separator)
            yield VmfsFilesystemEntry(self.fs, path, f)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a directory."""
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a file."""
        try:
            resolved = self._resolve(follow_symlinks=follow_symlinks)
            return resolved.entry.is_file() or resolved.entry.is_system()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return self.entry.is_symlink()

    def readlink(self) -> str:
        """Read the link of the given path if it is a symlink. Returns a string."""
        if not self.is_symlink():
            raise NotASymlinkError()

        return self.entry.link

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        node = self.entry.descriptor

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = [
            self.entry.mode,
            self.entry.address,
            id(self.fs),
            node.numLinks,
            node.uid,
            node.gid,
            node.length,
            node.accessTime,
            node.modificationTime,
            node.creationTime,
        ]

        return fsutil.stat_result(st_info)
