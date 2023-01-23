from __future__ import annotations

import logging
import stat
import zipfile
from datetime import datetime, timezone
from typing import BinaryIO, Optional

from dissect.util.stream import BufferedStream

from dissect.target.exceptions import FileNotFoundError, FilesystemError
from dissect.target.filesystem import Filesystem, VirtualFile, VirtualFilesystem
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
        alt_separator: str = "",
        case_sensitive: bool = True,
        *args,
        **kwargs,
    ):
        fh.seek(0)

        self.zip = zipfile.ZipFile(fh, mode="r")
        self.base = base or ""
        self.alt_separator = alt_separator

        self._fs = VirtualFilesystem(alt_separator=alt_separator, case_sensitive=case_sensitive)

        for member in self.zip.infolist():
            if member.is_dir():
                continue

            mname = member.filename.strip("/")
            if not mname.startswith(self.base):
                continue

            rel_name = fsutil.normpath(mname[len(self.base) :])

            # NOTE: Normally we would check here if the member is a symlink or not

            file_entry = ZipFilesystemEntry(self, rel_name, member)
            self._fs.map_file_entry(rel_name, file_entry)

        super().__init__(alt_separator=alt_separator, case_sensitive=case_sensitive, *args, **kwargs)

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        """Detect a zip file on a given file-like object."""
        offset = fh.tell()
        try:
            fh.seek(0)
            return zipfile.is_zipfile(fh)
        except Exception as e:
            log.warning("Failed to detect zip filesystem", exc_info=e)
            return False
        finally:
            fh.seek(offset)

    def get(self, path: str) -> ZipFilesystemEntry:
        """Returns a ZipFilesystemEntry object corresponding to the given path."""
        return self._fs.get(path)


class ZipFilesystemEntry(VirtualFile):
    def _resolve(self) -> ZipFilesystemEntry:
        return self

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        try:
            return BufferedStream(self.fs.zip.open(self.entry), size=self.entry.file_size)
        except Exception:
            raise FileNotFoundError()

    def is_dir(self) -> bool:
        """Return whether this entry is a directory. Resolves symlinks when possible."""
        try:
            return self._resolve().entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self) -> bool:
        """Return whether this entry is a file. Resolves symlinks when possible."""
        try:
            return not self.is_dir()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return False

    def readlink(self) -> str:
        """Read the link if this entry is a symlink. Returns a string."""
        raise NotImplementedError()

    def readlink_ext(self) -> ZipFilesystemEntry:
        """Read the link if this entry is a symlink. Returns a filesystem entry."""
        raise NotImplementedError()

    def stat(self) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self._resolve().lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                (stat.S_IFDIR if self.is_dir() else stat.S_IFREG) | 0o777,
                self.entry.header_offset,
                id(self.fs),
                0,
                0,
                0,
                self.entry.file_size,
                0,
                datetime(*self.entry.date_time, tzinfo=timezone.utc),
                0,
            ]
        )
