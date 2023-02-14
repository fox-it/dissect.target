import stat

from dissect.evidence import ad1

from dissect.target.exceptions import (
    FileNotFoundError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class AD1Filesystem(Filesystem):
    __fstype__ = "ad1"

    def __init__(self, fh, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.ad1 = ad1.AD1(fh)

    @staticmethod
    def _detect(fh):
        return fh.read(16) == b"ADSEGMENTEDFILE\x00"

    def get(self, path):
        return AD1FilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(self, path):
        try:
            return self.ad1.get(path)
        except IOError:
            raise FileNotFoundError(path)


class AD1FilesystemEntry(FilesystemEntry):
    def get(self, path):
        path = fsutil.join(self.path, path, alt_separator=self.alt_separator)
        return AD1FilesystemEntry(self.fs, path, self.fs._get_node(path, self.entry))

    def open(self):
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.entry.open()

    def iterdir(self):
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for file_ in self.entry.listdir().keys():
            yield file_

    def scandir(self):
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for fname, file_ in self.entry.listdir().items():
            path = fsutil.join(self.path, fname, alt_separator=self.alt_separator)
            yield AD1FilesystemEntry(self.fs, path, file_)

    def is_file(self):
        return self.entry.is_file()

    def is_dir(self):
        return self.entry.is_dir()

    def is_symlink(self):
        return False

    def readlink(self):
        raise NotASymlinkError()

    def readlink_ext(self):
        raise NotASymlinkError()

    def stat(self):
        return self.lstat()

    def lstat(self):
        size = self.entry.size if self.entry.is_file() else 0
        entry_addr = fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator)
        return fsutil.stat_result([stat.S_IFREG, entry_addr, id(self.fs), 0, 0, 0, size, 0, 0, 0])
