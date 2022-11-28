import logging
import struct

import dissect.vmfs as vmfs
from dissect.vmfs.c_vmfs import c_vmfs

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


class VmfsFilesystem(Filesystem):
    __fstype__ = "vmfs"

    def __init__(self, fh, *args, **kwargs):
        self.vmfs = vmfs.VMFS(fh)
        super().__init__(fh, *args, **kwargs)

    @staticmethod
    def detect(fh):
        """Detect a VMFS filesystem on a given file-like object."""
        offset = fh.tell()
        try:
            fh.seek(c_vmfs.VMFS_FS3_BASE)
            sector = fh.read(512)
            return struct.unpack("<I", sector[:4])[0] in (
                c_vmfs.VMFS_FS3_MAGIC,
                c_vmfs.VMFSL_FS3_MAGIC,
            )
        except Exception as e:
            log.warning("Failed to detect VMFS filesystem", exc_info=e)
            return False
        finally:
            fh.seek(offset)

    def get(self, path):
        """Returns a VmfsFilesystemEntry object corresponding to the given pathname"""
        return VmfsFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path, node=None):
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
    def _resolve(self):
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def get(self, path):
        """Get a filesystem entry relative from the current one."""
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return VmfsFilesystemEntry(self.fs, full_path, self.fs._get_node(path, self.entry))

    def open(self):
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open()

    def _iterdir(self):
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

    def iterdir(self):
        """List the directory contents of a directory. Returns a generator of strings."""
        for f in self._iterdir():
            yield f.name

    def scandir(self):
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        for f in self._iterdir():
            path = fsutil.join(self.path, f.name, alt_separator=self.fs.alt_separator)
            yield VmfsFilesystemEntry(self.fs, path, f)

    def is_dir(self):
        """Return whether this entry is a directory. Resolves symlinks when possible."""
        try:
            return self._resolve().entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self):
        """Return whether this entry is a file. Resolves symlinks when possible."""
        try:
            resolved = self._resolve()
            return resolved.entry.is_file() or resolved.entry.is_system()
        except FilesystemError:
            return False

    def is_symlink(self):
        """Return whether this entry is a link."""
        return self.entry.is_symlink()

    def readlink(self):
        """Read the link of the given path if it is a symlink. Returns a string."""
        if not self.is_symlink():
            raise NotASymlinkError()

        return self.entry.link

    def stat(self):
        """Return the stat information of this entry."""
        return self._resolve().lstat()

    def lstat(self):
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
