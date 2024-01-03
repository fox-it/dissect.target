import errno
import logging
from functools import lru_cache
from typing import BinaryIO, Optional

from dissect.util.feature import Feature, feature_enabled

if feature_enabled(Feature.BETA):
    from fusepy3.fuse import FuseOSError, LoggingMixIn, Operations
else:
    from fuse import FuseOSError, LoggingMixIn, Operations

from dissect.target.filesystem import Filesystem, FilesystemEntry

log = logging.getLogger(__name__)

CACHE_SIZE = 1024 * 1024


class DissectMount(Operations, LoggingMixIn):
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

    def getattr(self, path: str, buf, fh: Optional[int] = None) -> dict:
        fe = self._get(path)

        try:
            st = fe.lstat()
            data = dict(
                (key, getattr(st, key))
                for key in (
                    "st_atime",
                    "st_ctime",
                    "st_ino",
                    "st_gid",
                    "st_mode",
                    "st_mtime",
                    "st_nlink",
                    "st_size",
                    "st_uid",
                )
            )
            print(path, data, st)
            return data

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

    def readdir(self, path: str, fh: int, flags: int = 0):
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
        if file := self.file_handles.get(fh):
            file.close()

        del self.file_handles[fh]
        return 0

    def releasedir(self, path: str, fh: int) -> int:
        del self.dir_handles[fh]
        return 0

    if feature_enabled(Feature.BETA):

        def lseek(self, path: str, off: int, whence: int, fh: int) -> int:
            if file := self.file_handles.get(fh):
                return file.seek(off, whence)
        # def read_buf(self, path: str, size: int, off: int, fd: int) -> str:
        #     pass
