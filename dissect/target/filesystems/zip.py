from __future__ import annotations

import stat
import zipfile as zf
from datetime import datetime, timezone
from typing import TYPE_CHECKING, BinaryIO

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
        *,
        zipfile: zf.ZipFile | None = None,
        **kwargs,
    ):
        super().__init__(fh, **kwargs)

        if zipfile:
            self.zip = zipfile
        else:
            fh.seek(0)
            self.zip = zf.ZipFile(fh, mode="r")

        self.base = self._resolve_path(base) if base else ""
        if self.base and not self.base.endswith("/"):
            self.base += "/"

        # Ideally we just use zf.Path, but it doesn't handle absolute paths or relative paths (e.g., "./") correctly
        # We can at least steal the namelist with implied directories and go from there
        self._namemap = {}
        for name in zf.Path(self.zip).root.namelist():
            normalized = self._resolve_path(name)
            if self.base:
                if not normalized.startswith(self.base):
                    continue
                normalized = normalized.removeprefix(self.base)
            self._namemap[normalized] = name

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a zip file on a given file-like object."""
        return zf.is_zipfile(fh)

    def _resolve_path(self, path: str) -> str:
        if not self.case_sensitive:
            path = path.lower()

        return fsutil.normpath(path, alt_separator=self.alt_separator).lstrip("/")

    def get(self, path: str) -> FilesystemEntry:
        """Returns a ZipFilesystemEntry object corresponding to the given path."""
        path = fsutil.normpath(path.strip("/"))
        path = path.lower() if not self.case_sensitive else path
        if (normpath := self._namemap.get(path)) is None:
            if path == "":
                return ZipFilesystemEntry(self, "/", zf.ZipInfo(filename=self.base or "/"))
            raise FileNotFoundError(path)

        return ZipFilesystemEntry(self, path, self.zip.getinfo(normpath))


class ZipDirEntry(DirEntry):
    fs: ZipFilesystem
    entry: zf.ZipInfo

    def get(self) -> FilesystemEntry:
        return ZipFilesystemEntry(self.fs, self.path, self.entry)

    def stat(self, *, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class ZipFilesystemEntry(FilesystemEntry):
    fs: ZipFilesystem
    entry: zf.ZipInfo

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(fsutil.join(self.path, path, alt_separator=self.fs.alt_separator))

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)

        if self.is_symlink():
            return self._resolve().open()

        try:
            return self.fs.zip.open(self.entry)
        except Exception:
            raise FileNotFoundError(self.path)

    def _is_child(self, path: str) -> bool:
        if path == "":
            return False
        return fsutil.dirname(path.strip("/"), alt_separator=self.fs.alt_separator) == self.path.strip("/")

    def _iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext()._iterdir()
        else:
            yield from filter(self._is_child, self.fs._namemap.keys())

    def iterdir(self) -> Iterator[str]:
        yield from map(fsutil.basename, self._iterdir())

    def scandir(self) -> Iterator[DirEntry]:
        for name in self._iterdir():
            entry = self.fs.zip.getinfo(self.fs._namemap.get(name, name))
            yield ZipDirEntry(self.fs, self.path, fsutil.basename(name), entry)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return not self.is_dir(follow_symlinks=follow_symlinks)

    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.lstat().st_mode)

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError
        return self.fs.zip.open(self.entry).read().decode("utf-8")

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        info = self.entry

        if not (mode := info.external_attr >> 16):
            mode = 0o777

        if info.is_dir() and not stat.S_ISDIR(mode):
            mode = stat.S_IFDIR | mode
        elif not info.is_dir() and not stat.S_ISREG(mode):
            mode = stat.S_IFREG | mode

        try:
            mtime = datetime(*info.date_time, tzinfo=timezone.utc)
        except ValueError:
            mtime_tuple = (2107, 12, 31, 23, 59, 59) if info.date_time[0] >= 2107 else (1980, 1, 1, 0, 0, 0)
            mtime = datetime(*mtime_tuple, tzinfo=timezone.utc)

        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                mode,
                getattr(info, "header_offset", id(info)),
                id(self.fs),
                1,
                0,
                0,
                info.file_size,
                0,
                mtime.timestamp(),
                0,
            ]
        )
