from __future__ import annotations

import logging
import stat
import tarfile
from typing import BinaryIO, Optional

from dissect.util.stream import BufferedStream

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import (
    Filesystem,
    VirtualDirectory,
    VirtualFile,
    VirtualFilesystem,
)
from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


class TarFilesystem(Filesystem):
    """Filesystem implementation for tar files."""

    __fstype__ = "tar"

    def __init__(
        self,
        fh: BinaryIO,
        base: Optional[str] = None,
        tarinfo: Optional[tarfile.TarInfo] = None,
        *args,
        **kwargs,
    ):
        super().__init__(fh, *args, **kwargs)
        fh.seek(0)

        self.tar = tarfile.open(mode="r", fileobj=fh, tarinfo=tarinfo)
        self.base = base or ""

        self._fs = VirtualFilesystem(alt_separator=self.alt_separator, case_sensitive=self.case_sensitive)

        for member in self.tar.getmembers():
            mname = member.name.strip("/")
            if not mname.startswith(self.base) or mname == ".":
                continue

            rel_name = fsutil.normpath(mname[len(self.base) :], alt_separator=self.alt_separator)

            entry_cls = TarFilesystemDirectoryEntry if member.isdir() else TarFilesystemEntry
            file_entry = entry_cls(self, rel_name, member)
            self._fs.map_file_entry(rel_name, file_entry)

    @staticmethod
    def detect(fh) -> bool:
        """Detect a tar file on a given file-like object."""
        offset = fh.tell()
        try:
            fh.seek(0)
            return tarfile.is_tarfile(fh)
        except Exception as e:
            log.warning("Failed to detect tar filesystem", exc_info=e)
            return False
        finally:
            fh.seek(offset)

    def get(self, path) -> TarFilesystemEntry:
        """Returns a TarFilesystemEntry object corresponding to the given path."""
        return self._fs.get(path)


class TarFilesystemEntry(VirtualFile):
    def _resolve(self) -> TarFilesystemEntry:
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)

        try:
            f = self.fs.tar.extractfile(self.entry)
            if hasattr(f, "raw"):
                f.size = f.raw.size
            return BufferedStream(f, size=f.size)
        except Exception:
            raise FileNotFoundError()

    def iterdir(self):
        if self.is_dir():
            return self._resolve().iterdir()
        return super().iterdir()

    def scandir(self):
        if self.is_dir():
            return self._resolve().scandir()
        return super().scandir()

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
        if not self.is_symlink():
            raise NotASymlinkError()
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
                (stat.S_IFLNK if self.entry.issym() else stat.S_IFREG) | self.entry.mode,
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


class TarFilesystemDirectoryEntry(VirtualDirectory):
    def __init__(self, fs: TarFilesystem, path: str, entry: tarfile.TarInfo):
        super().__init__(fs, path)
        self.entry = entry

    def stat(self) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        return fsutil.stat_result(
            [
                stat.S_IFDIR | self.entry.mode,
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
