from __future__ import annotations

import stat
from datetime import datetime
from typing import TYPE_CHECKING, BinaryIO, Iterator

from cbc_sdk.live_response_api import LiveResponseError

from dissect.target.exceptions import FileNotFoundError, NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from pathlib import Path

    from cbc_sdk.live_response_api import LiveResponseSession
    from cbc_sdk.platform import Device
    from cbc_sdk.rest_api import CBCloudAPI

    from dissect.target.helpers.fsutil import stat_result


EPOCH = datetime(1970, 1, 1)
CB_TIMEFORMAT = "%Y-%m-%dT%H:%M:%S%fZ"


class CbFilesystem(Filesystem):
    __fstype__ = "cb"

    def __init__(self, cb: CBCloudAPI, sensor: Device, session: LiveResponseSession, prefix: str):
        self.cb = cb
        self.sensor = sensor
        self.session = session
        self.prefix = prefix
        super().__init__(volume=prefix)

    @staticmethod
    def detect(fh: BinaryIO):
        raise TypeError("Detect is not allowed on CbFilesystem class")

    def get(self, path: Path) -> CbFilesystemEntry:
        """Returns a CbFilesystemEntry object corresponding to the given pathname."""
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
    def get(self, path: str) -> CbFilesystemEntry:
        """Get a filesystem entry relative from the current one."""
        full_path = fsutil.join(self.path, path)
        return self.fs.get(full_path)

    def open(self) -> bytes:
        """Open the file on the location that is currently set as path."""
        return self.fs.session.get_raw_file(self.path)

    def iterdir(self) -> Iterator[str]:
        """Iterate over the entries of a directory and return the name."""
        for f in self.scandir():
            yield f.name

    def scandir(self) -> Iterator[CbFilesystemEntry]:
        """Iterate over the entries within a given directory."""
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

            yield CbFilesystemEntry(self.fs, fsutil.join(path, f["filename"]), f)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return "DIRECTORY" in self.entry["attributes"]

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return "ARCHIVE" in self.entry["attributes"]

    def is_symlink(self) -> bool:
        return False

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        mode = stat.S_IFDIR if self.is_dir() else stat.S_IFREG
        last_access = int((datetime.strptime(self.entry["last_access_time"], CB_TIMEFORMAT) - EPOCH).total_seconds())
        last_write = int((datetime.strptime(self.entry["last_write_time"], CB_TIMEFORMAT) - EPOCH).total_seconds())

        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        st_info = [
            mode | 0o755,
            0,
            0,
            0,
            0,
            0,
            self.entry["size"],
            last_access,
            last_write,
            last_write,
        ]
        return fsutil.stat_result(st_info)

    def readlink(self):
        raise NotImplementedError()

    def readlink_ext(self):
        raise NotImplementedError()

    def attr(self):
        raise TypeError(f"attr is not allowed on CbFilesystemEntry: {self.path}")

    def lattr(self):
        raise TypeError(f"lattr is not allowed on CbFilesystemEntry: {self.path}")
