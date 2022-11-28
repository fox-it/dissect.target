import stat

from cbapi.live_response_api import LiveResponseError

from dissect.target.exceptions import FileNotFoundError, NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class CbFilesystem(Filesystem):
    __fstype__ = "cb"

    def __init__(self, cb, sensor, session, prefix):
        self.cb = cb
        self.sensor = sensor
        self.session = session
        self.prefix = prefix
        super().__init__()

    @staticmethod
    def detect(fh):
        raise TypeError("Detect is not allowed on CbFilesystem class")

    def get(self, path):
        path = path.strip("/")

        if self.session.os_type == 1:
            cbpath = path.replace("/", "\\")
        else:
            cbpath = path

        if self.prefix and not cbpath.lower().startswith(self.prefix.lower()):
            cbpath = self.prefix + cbpath

        try:
            res = self.session.list_directory(cbpath)
            if len(res) == 1:
                entry = res[0]
            else:
                # Root entries return the full dirlisting, make up our own entry
                entry = {
                    "filename": "\\",
                    "attributes": ["DIRECTORY"],
                    "last_access_time": 0,
                    "last_write_time": 0,
                    "size": 0,
                }

            return CbFilesystemEntry(self, cbpath, entry)
        except LiveResponseError:
            raise FileNotFoundError(path)


class CbFilesystemEntry(FilesystemEntry):
    def get(self, path):
        fullpath = self.fs.session.path_join(self.path, path)
        return self.fs.get(fullpath)

    def open(self):
        return self.fs.session.get_raw_file(self.path)

    def iterdir(self):
        for f in self.scandir():
            yield f.name

    def scandir(self):
        if not self.is_dir():
            raise NotADirectoryError(f"'{self.path}' is not a directory")

        if self.fs.session.os_type == 1:
            stripped_path = self.path.rstrip("\\")
            path = f"{stripped_path}\\"
        else:
            path = f"{self.path.rstrip('/')}/"

        for f in self.fs.session.list_directory(path):
            if f["filename"] in (".", ".."):
                continue

            yield CbFilesystemEntry(self.fs, self.fs.session.path_join(path, f["filename"]), f)

    def is_dir(self):
        return "DIRECTORY" in self.entry["attributes"]

    def is_file(self):
        return "ARCHIVE" in self.entry["attributes"]

    def is_symlink(self):
        return False

    def stat(self):
        mode = stat.S_IFDIR if self.is_dir() else stat.S_IFREG

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = [
            mode | 0o755,
            fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator),
            id(self.fs),
            0,
            0,
            0,
            self.entry["size"],
            self.entry["last_access_time"],
            self.entry["last_write_time"],
            self.entry["last_write_time"],
        ]
        return fsutil.stat_result(st_info)

    def readlink(self):
        raise NotImplementedError()

    def readlink_ext(self):
        raise NotImplementedError()

    def lstat(self):
        raise NotImplementedError()

    def attr(self):
        raise TypeError(f"attr is not allowed on CbFilesystemEntry: {self.path}")

    def lattr(self):
        raise TypeError(f"lattr is not allowed on CbFilesystemEntry: {self.path}")
