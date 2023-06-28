from __future__ import annotations

import logging
import stat
import zipfile
from datetime import datetime, timezone
from typing import BinaryIO, Optional

from dissect.util.stream import BufferedStream

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import (
    Filesystem,
    FilesystemEntry,
    VirtualDirectory,
    VirtualFile,
    VirtualFilesystem,
)
from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


class ZipFilesystem(Filesystem):
    """Filesystem implementation for zip files.

    Python does not have symlink support in the zipfile module, so that's not currently supported.
    See https://github.com/python/cpython/issues/82102 for more information.
    """

    __fstype__ = "zip"

    def __init__(
        self,
        fh: BinaryIO,
        base: Optional[str] = None,
        *args,
        **kwargs,
    ):
        super().__init__(fh, *args, **kwargs)

        fh.seek(0)

        self.zip = zipfile.ZipFile(fh, mode="r")
        self.base = base or ""

        self._fs = VirtualFilesystem(alt_separator=self.alt_separator, case_sensitive=self.case_sensitive)

        for member in self.zip.infolist():
            mname = member.filename.strip("/")
            if not mname.startswith(self.base) or mname == ".":
                continue

            rel_name = fsutil.normpath(mname[len(self.base) :], alt_separator=self.alt_separator)

            # NOTE: Normally we would check here if the member is a symlink or not

            entry_cls = ZipFilesystemDirectoryEntry if member.is_dir() else ZipFilesystemEntry
            file_entry = entry_cls(self, rel_name, member)
            self._fs.map_file_entry(rel_name, file_entry)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a zip file on a given file-like object."""
        return zipfile.is_zipfile(fh)

    def get(self, path: str, relentry: FilesystemEntry = None) -> FilesystemEntry:
        """Returns a ZipFilesystemEntry object corresponding to the given path."""
        return self._fs.get(path, relentry=relentry)


class ZipFilesystemEntry(VirtualFile):
    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        try:
            return BufferedStream(self.fs.zip.open(self.entry), size=self.entry.file_size)
        except Exception:
            raise FileNotFoundError()

    def readlink(self) -> str:
        """Read the link if this entry is a symlink. Returns a string."""
        raise NotImplementedError()

    def readlink_ext(self) -> FilesystemEntry:
        """Read the link if this entry is a symlink. Returns a filesystem entry."""
        raise NotImplementedError()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                stat.S_IFREG | 0o777,
                self.entry.header_offset,
                id(self.fs),
                0,
                0,
                0,
                self.entry.file_size,
                0,
                datetime(*self.entry.date_time, tzinfo=timezone.utc).timestamp(),
                0,
            ]
        )


class ZipFilesystemDirectoryEntry(VirtualDirectory):
    def __init__(self, fs: ZipFilesystem, path: str, entry: zipfile.ZipInfo):
        super().__init__(fs, path)
        self.entry = entry

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                stat.S_IFDIR | 0o777,
                self.entry.header_offset,
                id(self.fs),
                0,
                0,
                0,
                self.entry.file_size,
                0,
                datetime(*self.entry.date_time, tzinfo=timezone.utc).timestamp(),
                0,
            ]
        )
