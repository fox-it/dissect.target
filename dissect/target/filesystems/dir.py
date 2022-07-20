import os

from dissect.target.exceptions import FileNotFoundError, FilesystemError, IsADirectoryError, NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class DirectoryFilesystem(Filesystem):
    __fstype__ = "dir"

    def __init__(self, path, case_sensitive=True):
        self.base_path = path
        super().__init__(case_sensitive=case_sensitive)

    @staticmethod
    def detect(fh):
        raise TypeError("Detect is not allowed on DirectoryFilesystem class")

    def get(self, path):
        path = path.strip("/")

        if not path:
            return DirectoryFilesystemEntry(self, "/", self.base_path)

        if not self.case_sensitive:
            searchpath = self.base_path

            for p in path.split("/"):
                match = [d for d in searchpath.iterdir() if d.name.lower() == p.lower()]

                if not match or len(match) > 1:
                    raise FileNotFoundError(path)

                searchpath = match[0]

            entry = searchpath
        else:
            entry = self.base_path.joinpath(path.strip("/"))

        try:
            entry.lstat()
            return DirectoryFilesystemEntry(self, path, entry)
        except Exception:
            raise FileNotFoundError(path)

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.base_path}>"


class DirectoryFilesystemEntry(FilesystemEntry):
    def _resolve(self):
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def get(self, path):
        return self.fs.get(fsutil.join(self.path, path))

    def open(self):
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open("rb")

    def iterdir(self):
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().iterdir()
        else:
            for item in self.entry.iterdir():
                yield item.name

    def scandir(self):
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().scandir()
        else:
            for item in self.entry.iterdir():
                yield DirectoryFilesystemEntry(self.fs, fsutil.join(self.path, item.name), item)

    def exists(self):
        try:
            return self._resolve().entry.exists()
        except FilesystemError:
            return False

    def is_dir(self):
        try:
            return self._resolve().entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self):
        try:
            return self._resolve().entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self):
        return self.entry.is_symlink()

    def readlink(self):
        return os.readlink(self.entry)  # Python 3.7 compatibility

    def stat(self):
        return self._resolve().entry.lstat()

    def lstat(self):
        return fsutil.stat_result.copy(self.entry.lstat())

    def attr(self):
        raise TypeError()

    def lattr(self):
        raise TypeError()
