from __future__ import annotations

import logging
import tarfile
from typing import BinaryIO, Union

from dissect.util.stream import BufferedStream
from dissect.target.exceptions import FileNotFoundError, FilesystemError
from dissect.target.filesystem import (
    Filesystem,
    FilesystemEntry,
    VirtualDirectory,
    VirtualFile,
    VirtualFilesystem,
)
from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


class TarFilesystem(Filesystem):
    """Filesystem implementation for tar files.

    Makes use of cpython's tarfile module.
    https://docs.python.org/3/library/tarfile.html
    """

    __fstype__ = "tar"

    def __init__(self, fh, base=None, alt_separator: str = "", case_sensitive=True, tarinfo=None, *args, **kwargs):
        super().__init__(alt_separator=alt_separator, case_sensitive=case_sensitive, *args, **kwargs)
        fh.seek(0)

        self.tar = tarfile.open(mode="r", fileobj=fh, tarinfo=tarinfo)
        self.base = base.strip("/") if base else ""

        self._fs = VirtualFilesystem(case_sensitive=case_sensitive)

        for member in self.tar.getmembers():
            if member.isdir():
                VirtualDirectory.__init__(self, self._fs, member)

            mname = member.name.strip("/")
            if not mname.startswith(self.base):
                continue

            rel_name = fsutil.normpath(mname[len(self.base) :], alt_separator=self.alt_separator)

            if member.issym():
                # Do we need to trim the link name for relative tar bases or not?
                self._fs.symlink(member.linkname, mname)
            else:
                file_entry = TarFilesystemEntry(self, rel_name, member)
                self._fs.map_file_entry(rel_name, file_entry)

    @staticmethod
    def detect(fh) -> bool:
        """Detect a tar file on a given file-like object."""
        offset = fh.tell()
        try:
            fh.seek(0)
            tarfile.TarFile(fileobj=fh, mode="r")
            return True
        except Exception as e:
            log.warning("Failed to detect tar filesystem", exc_info=e)
            return False
        finally:
            fh.seek(offset)

    def get(self, path) -> TarFilesystemEntry:
        """Returns a TarFilesystemEntry object corresponding to the given path."""
        return self._fs.get(path)


class TarFilesystemEntry(VirtualDirectory, VirtualFile):
    def __init__(self, fs: Filesystem, path: str, entry: tarfile.TarInfo):
        if entry.isdir():
            VirtualDirectory.__init__(self, fs, path)
        FilesystemEntry.__init__(self, fs, path, entry)

    def _resolve(self) -> TarFilesystemEntry:
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_file():
            try:
                f = self.fs.tar.extractfile(self.entry)
                if hasattr(f, "raw"):
                    f.size = f.raw.size
                return BufferedStream(f, size=f.size)
            except Exception:
                raise FileNotFoundError()
        else:
            return super(VirtualDirectory, self).open()

    def is_dir(self) -> bool:
        """Return whether this entry is a directory. Resolves symlinks when possible."""
        try:
            return self._resolve().entry.isdir()
        except FilesystemError:
            return False

    def is_file(self) -> bool:
        """Return whether this entry is a file. Resolves symlinks when possible."""
        try:
            return self._resolve().entry.isfile()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return self.entry.issym()

    def readlink(self):
        """Read the link if this entry is a symlink. Returns a string."""
        return self.entry.linkname

    def readlink_ext(self) -> TarFilesystemEntry:
        """Read the link if this entry is a symlink. Returns a filesystem entry."""
        # Can't use the one in VirtualFile as it overrides the FilesystemEntry
        return fsutil.resolve_link(fs=self.fs, entry=self)

    def stat(self) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self._resolve().lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        return fsutil.stat_result(
            [
                self.entry.mode,
                self.entry.offset,
                id(self.fs),
                0,
                self.entry.uid,
                self.entry.gid,
                self.entry.size,
                0,
                self.entry.mtime,
                0,
            ]
        )
