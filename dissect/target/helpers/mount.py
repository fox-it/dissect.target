import errno
import logging
from stat import S_IFDIR, S_IFREG
from functools import lru_cache

from fuse import FuseOSError, Operations

from dissect.target import filesystem

log = logging.getLogger(__name__)


class DissectMount(Operations):
    def __init__(self, fs):
        self.fs = fs

    def _get(self, path):
        try:
            return self.fs.get(path)
        except Exception:
            raise FuseOSError(errno.ENOENT)

    @lru_cache(4096)
    def getattr(self, path, fh=None):
        log.debug("fuse::getattr(%s, %s)", path, fh)

        fe = self._get(path)

        try:
            st = fe.stat()
            ret = dict(
                (key, getattr(st, key))
                for key in ("st_atime", "st_ctime", "st_gid", "st_mode", "st_mtime", "st_nlink", "st_size", "st_uid")
            )
        except NotImplementedError:
            ret = {
                "st_atime": 0,
                "st_ctime": 0,
                "st_gid": 0,
                "st_mode": ((S_IFDIR if fe.is_dir() else S_IFREG) | 0o755),
                "st_mtime": 0,
                "st_nlink": 0,
                "st_size": fe.entry.size if fe.is_file() and isinstance(fe, filesystem.VirtualFile) else 0,
                "st_uid": 0,
            }
        except Exception:
            log.exception("Exception in fuse::getattr")
            raise FuseOSError(errno.EIO)

        return ret

    getxattr = None

    listxattr = None

    def read(self, path, size, offset, fh):
        log.debug("fuse::read(%s, %d, %d, %s)" % (path, size, offset, fh))
        fe = self._get(path)

        try:
            fh = fe.open()
            fh.seek(offset)
            return fh.read(size)
        except Exception:
            log.exception("Exception in fuse::read")
            raise FuseOSError(errno.EIO)

    def readdir(self, path, fh):  # noqa
        log.debug("fuse::readdir(%s)", path)
        fe = self._get(path)

        try:
            dirs = [".", ".."] + [str(x) for x in fe.listdir()]

            for d in dirs:
                yield d
        except Exception:
            log.exception("Exception in fuse::readdir")
            raise FuseOSError(errno.EIO)

    def readlink(self, path):
        log.debug("fuse::readlink(%s)", path)
        fe = self._get(path)

        try:
            return fe.readlink()
        except Exception:
            raise FuseOSError(errno.EIO)
