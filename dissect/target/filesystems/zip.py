from __future__ import annotations

import logging
import stat
import zipfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import BufferedStream

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import (
    Filesystem,
    FilesystemEntry,
    VirtualDirectory,
    VirtualFilesystem,
)
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator

log = logging.getLogger(__name__)


class ZipFilesystem(Filesystem):
    """Filesystem implementation for zip files.

    Python does not have symlink support in the zipfile module, so that's not currently supported.
    See https://github.com/python/cpython/issues/82102 for more information.
    """

    __type__ = "zip"

    def __init__(
        self,
        fh: BinaryIO,
        base: str | None = None,
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

            rel_name = self._resolve_path(mname)
            self._fs.map_file_entry(rel_name, ZipFilesystemEntry(self, rel_name, member))

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a zip file on a given file-like object."""
        return zipfile.is_zipfile(fh)

    def _resolve_path(self, path: str) -> str:
        return fsutil.normpath(path[len(self.base) :], alt_separator=self.alt_separator)

    def get(self, path: str, relentry: FilesystemEntry = None) -> FilesystemEntry:
        """Returns a ZipFilesystemEntry object corresponding to the given path."""
        return self._fs.get(path, relentry=relentry)


# Note: We subclass from VirtualDirectory because VirtualFilesystem is currently only compatible with VirtualDirectory
# Subclass from VirtualDirectory so we get that compatibility for free, and override the rest to do our own thing
class ZipFilesystemEntry(VirtualDirectory):
    fs: ZipFilesystem
    entry: zipfile.ZipInfo

    def __init__(self, fs: ZipFilesystem, path: str, entry: zipfile.ZipInfo):
        super().__init__(fs, path)
        self.entry = entry

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)

        if self.is_symlink():
            return self._resolve().open()

        try:
            return BufferedStream(self.fs.zip.open(self.entry), size=self.entry.file_size)
        except Exception:
            raise FileNotFoundError(self.path)

    def iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        entry = self._resolve()
        if isinstance(entry, ZipFilesystemEntry):
            yield from super(ZipFilesystemEntry, entry).iterdir()
        else:
            yield from entry.iterdir()

    def scandir(self) -> Iterator[FilesystemEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        entry = self._resolve()
        if isinstance(entry, ZipFilesystemEntry):
            yield from super(ZipFilesystemEntry, entry).scandir()
        else:
            yield from entry.scandir()

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            entry = self._resolve(follow_symlinks=follow_symlinks)
        except FilesystemError:
            return False

        if isinstance(entry, ZipFilesystemEntry):
            return entry.entry.is_dir()
        return isinstance(entry, VirtualDirectory)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            entry = self._resolve(follow_symlinks=follow_symlinks)
        except FilesystemError:
            return False

        if isinstance(entry, ZipFilesystemEntry):
            return not entry.entry.is_dir()
        return False

    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.entry.external_attr >> 16)

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError
        return self.fs.zip.open(self.entry).read().decode()

    def readlink_ext(self) -> FilesystemEntry:
        return FilesystemEntry.readlink_ext(self)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        mode = self.entry.external_attr >> 16

        if self.entry.is_dir() and not stat.S_ISDIR(mode):
            mode = stat.S_IFDIR | mode
        elif not self.entry.is_dir() and not stat.S_ISREG(mode):
            mode = stat.S_IFREG | mode

        return fsutil.stat_result(
            [
                mode,
                self.entry.header_offset,
                id(self.fs),
                1,
                0,
                0,
                self.entry.file_size,
                0,
                datetime(*self.entry.date_time, tzinfo=timezone.utc).timestamp(),
                0,
            ]
        )
