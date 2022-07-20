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
        self.ad1 = ad1.AD1(fh)
        super().__init__(fh, *args, **kwargs)

    @staticmethod
    def detect(fh):
        try:
            offset = fh.tell()
            magic = fh.read(16)
            fh.seek(offset)

            return magic == b"ADSEGMENTEDFILE\x00"
        except Exception:
            return False

    def get(self, path):
        return AD1FilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(self, path):
        try:
            return self.ad1.get(path)
        except IOError:
            raise FileNotFoundError(path)


class AD1FilesystemEntry(FilesystemEntry):
    def get(self, path):
        return AD1FilesystemEntry(self.fs, fsutil.join(self.path, path), self.fs._get_node(path, self.entry))

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
            yield AD1FilesystemEntry(self.fs, f"{self.path}/{fname}", file_)

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
        return fsutil.stat_result([stat.S_IFREG, fsutil.generate_addr(self.path), id(self.fs), 0, 0, 0, size, 0, 0, 0])
