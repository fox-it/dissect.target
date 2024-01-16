import errno
import logging
from functools import lru_cache
from typing import BinaryIO, Optional

from fuse import FuseOSError, Operations

from dissect.target.filesystem import Filesystem, FilesystemEntry

log = logging.getLogger(__name__)

CACHE_SIZE = 1024 * 1024


class DissectMount(Operations):
    def __init__(self, fs: Filesystem):
        self.fs = fs
        self.file_handles: dict[int, BinaryIO] = {}
        self.dir_handles: dict[int, FilesystemEntry] = {}

        self._get = lru_cache(CACHE_SIZE)(self._get)
        self.getattr = lru_cache(CACHE_SIZE)(self.getattr)

    def _get(self, path: str) -> FilesystemEntry:
        try:
            return self.fs.get(path)
        except Exception:
            raise FuseOSError(errno.ENOENT)

    def getattr(self, path: str, fh: Optional[int] = None) -> dict:
        fe = self._get(path)

        try:
            st = fe.lstat()
            return dict(
                (key, getattr(st, key))
                for key in ("st_atime", "st_ctime", "st_gid", "st_mode", "st_mtime", "st_nlink", "st_size", "st_uid")
            )
        except Exception:
            raise FuseOSError(errno.EIO)

    getxattr = None

    listxattr = None

    def open(self, path: str, flags: int) -> int:
        entry = self._get(path)

        try:
            fh = entry.open()
        except Exception:
            raise FuseOSError(errno.ENOENT)

        fno = id(fh)
        self.file_handles[fno] = fh
        return fno

    def opendir(self, path: str) -> int:
        entry = self._get(path)

        fno = id(entry)
        self.dir_handles[fno] = entry
        return fno

    def read(self, path: str, size: int, offset: int, fh: int):
        if fh not in self.file_handles:
            raise FuseOSError(errno.EBADFD)

        fobj = self.file_handles[fh]

        try:
            fobj.seek(offset)
            return fobj.read(size)
        except Exception:
            log.exception("Exception in fuse::read")
            raise FuseOSError(errno.EIO)

    def readdir(self, path: str, fh: int):
        if fh not in self.dir_handles:
            raise FuseOSError(errno.EBADFD)

        fobj = self.dir_handles[fh]

        try:
            yield "."
            yield ".."

            for entry in fobj.iterdir():
                yield entry
        except Exception:
            log.exception("Exception in fuse::readdir")
            raise FuseOSError(errno.EIO)

    def readlink(self, path: str) -> str:
        fe = self._get(path)

        try:
            return fe.readlink()
        except Exception:
            raise FuseOSError(errno.EIO)

    def release(self, path: str, fh: int) -> int:
        del self.file_handles[fh]

    def releasedir(self, path: str, fh: int) -> int:
        del self.dir_handles[fh]
