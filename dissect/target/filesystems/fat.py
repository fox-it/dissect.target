import datetime
import logging
import stat

from dissect.fat import exceptions as fat_exc
from dissect.fat import fat

from dissect.target.exceptions import FileNotFoundError, NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


class FatFilesystem(Filesystem):
    __fstype__ = "fat"

    def __init__(self, fh=None, *args, **kwargs):
        self.fatfs = fat.FATFS(fh)
        # FAT timestamps are in local time, so to prevent skewing them even more, we specify UTC by default.
        # However, it should be noted that they are not actual UTC timestamps!
        # Implementers can optionally set the tzinfo attribute of this class to get correct UTC timestamps.
        self.tzinfo = datetime.timezone.utc
        super().__init__(case_sensitive=False, alt_separator="\\", *args, **kwargs)

    @staticmethod
    def detect(fh):
        """Detect a FAT filesystem on a given file-like object."""
        try:
            offset = fh.tell()
            fh.seek(0)
            buf = fh.read(512)
            fh.seek(offset)

            fat.validate_bpb(buf)
            return True
        except fat_exc.InvalidBPB:
            return False
        except Exception as e:
            log.warning("Failed to detect FAT filesystem", exc_info=e)
            return False

    def get(self, path):
        """Returns a FatFilesystemEntry object corresponding to the given pathname"""
        return FatFilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(self, path, entry=None):
        """Returns an internal FAT entry for a given path and optional relative entry."""
        try:
            return self.fatfs.get(path, dirent=entry)
        except fat_exc.FileNotFoundError as e:
            raise FileNotFoundError(path, cause=e)
        except fat_exc.NotADirectoryError as e:
            raise NotADirectoryError(path, cause=e)
        except fat_exc.Error as e:
            raise FileNotFoundError(path, cause=e)


class FatFilesystemEntry(FilesystemEntry):
    def get(self, path):
        """Get a filesystem entry relative from the current one."""
        return FatFilesystemEntry(self.fs, fsutil.join(self.path, path), self.fs._get_entry(path, self.entry))

    def open(self):
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.entry.open()

    def iterdir(self):
        """List the directory contents of a directory. Returns a generator of strings."""
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for f in self.entry.iterdir():
            if f.name in (".", ".."):
                continue
            yield f.name

    def scandir(self):
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for f in self.entry.iterdir():
            if f.name in (".", ".."):
                continue
            yield FatFilesystemEntry(self.fs, fsutil.join(self.path, f.name), f)

    def is_symlink(self):
        """Return whether this entry is a link."""
        return False

    def is_dir(self):
        """Return whether this entry is a directory. Resolves symlinks when possible."""
        return self.entry.is_directory()

    def is_file(self):
        """Return whether this entry is a file. Resolves symlinks when possible."""
        return not self.is_dir()

    def stat(self):
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self):
        """Return the stat information of the given path, without resolving links."""
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = [
            (stat.S_IFDIR if self.is_dir() else stat.S_IFREG) | 0o777,
            self.entry.cluster,
            id(self.fs),
            0,
            0,
            0,
            self.entry.size,
            self.entry.atime.replace(tzinfo=self.fs.tzinfo).timestamp(),
            self.entry.mtime.replace(tzinfo=self.fs.tzinfo).timestamp(),
            self.entry.ctime.replace(tzinfo=self.fs.tzinfo).timestamp(),
        ]
        return fsutil.stat_result(st_info)
