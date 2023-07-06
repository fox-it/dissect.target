from __future__ import annotations

import stat
from datetime import datetime
from enum import IntEnum
from typing import Any, BinaryIO, Iterator

from cbc_sdk.live_response_api import LiveResponseError, LiveResponseSession
from dissect.util import ts

from dissect.target.exceptions import FileNotFoundError, NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

EPOCH = datetime(1970, 1, 1)
CB_TIMEFORMAT = "%Y-%m-%dT%H:%M:%S%fZ"


class OS(IntEnum):
    WINDOWS = 1
    LINUX = 2
    MAC = 4


class CbFilesystem(Filesystem):
    __fstype__ = "cb"

    def __init__(self, session: LiveResponseSession, prefix: str, *args, **kwargs):
        self.session = session
        self.prefix = prefix.lower()

        if self.session.os_type == OS.WINDOWS:
            alt_separator = "\\"
            case_sensitive = False
        else:
            alt_separator = ""
            case_sensitive = True

        super().__init__(alt_separator=alt_separator, case_sensitive=case_sensitive, *args, **kwargs)

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on CbFilesystem class")

    def get(self, path: str) -> CbFilesystemEntry:
        """Returns a CbFilesystemEntry object corresponding to the given path."""
        cbpath = fsutil.normalize(path, alt_separator=self.alt_separator).strip("/")
        if self.session.os_type == OS.WINDOWS:
            cbpath = cbpath.replace("/", "\\")

        cbpath = self.prefix + cbpath

        try:
            if cbpath == self.prefix:
                # Root entries behave funky, so make up our own entry
                entry = {
                    "filename": self.prefix,
                    "attributes": ["DIRECTORY"],
                    "last_access_time": "1970-01-01T00:00:00Z",
                    "last_write_time": "1970-01-01T00:00:00Z",
                    "create_time": "1970-01-01T00:00:00Z",
                    "size": 0,
                }
            else:
                res = self.session.list_directory(cbpath)
                if len(res) == 1:
                    entry = res[0]

            return CbFilesystemEntry(self, path, entry, cbpath)
        except LiveResponseError:
            raise FileNotFoundError(path)


class CbFilesystemEntry(FilesystemEntry):
    def __init__(self, fs: Filesystem, path: str, entry: Any, cbpath: str) -> None:
        super().__init__(fs, path, entry)
        self.cbpath = cbpath

    def get(self, path: str) -> CbFilesystemEntry:
        """Get a filesystem entry relative from the current one."""
        full_path = fsutil.join(self.path, path)
        return self.fs.get(full_path)

    def open(self) -> bytes:
        """Returns file handle (file-like object)."""
        return self.fs.session.get_raw_file(self.cbpath)

    def iterdir(self) -> Iterator[str]:
        """List the directory contents of a directory. Returns a generator of strings."""
        for f in self.scandir():
            yield f.name

    def scandir(self) -> Iterator[CbFilesystemEntry]:
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        if not self.is_dir():
            raise NotADirectoryError(f"'{self.path}' is not a directory")

        seperator = "\\" if self.fs.session.os_type == OS.WINDOWS else "/"
        for entry in self.fs.session.list_directory(self.cbpath + seperator):
            if entry["filename"] in (".", ".."):
                continue

            path = fsutil.join(self.path, entry["filename"], alt_separator=self.fs.alt_separator)
            cbpath = seperator.join([self.cbpath, entry["filename"]])
            yield CbFilesystemEntry(self.fs, path, entry, cbpath)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a directory."""
        return "DIRECTORY" in self.entry["attributes"]

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a file."""
        return "ARCHIVE" in self.entry["attributes"]

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return False

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        mode = stat.S_IFDIR if self.is_dir() else stat.S_IFREG

        atime = ts.to_unix(datetime.strptime(self.entry["last_access_time"], CB_TIMEFORMAT))
        mtime = ts.to_unix(datetime.strptime(self.entry["last_write_time"], CB_TIMEFORMAT))
        ctime = ts.to_unix(datetime.strptime(self.entry["create_time"], CB_TIMEFORMAT))

        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        st_info = [
            mode | 0o755,
            fsutil.generate_addr(self.cbpath),
            id(self.fs),
            0,
            0,
            0,
            self.entry["size"],
            atime,
            mtime,
            ctime,
        ]
        return fsutil.stat_result(st_info)
