from __future__ import annotations

import stat
from typing import BinaryIO, Iterator, Optional

from dissect.ntfs import NTFS, NTFS_SIGNATURE, IndexEntry, MftRecord
from dissect.ntfs.exceptions import Error as NtfsError
from dissect.ntfs.exceptions import FileNotFoundError as NtfsFileNotFoundError
from dissect.ntfs.exceptions import NotADirectoryError as NtfsNotADirectoryError
from dissect.ntfs.util import AttributeMap

from dissect.target.exceptions import (
    FileNotFoundError,
    IsADirectoryError,
    NotADirectoryError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class NtfsFilesystem(Filesystem):
    __fstype__ = "ntfs"

    def __init__(
        self,
        fh: Optional[BinaryIO] = None,
        boot: Optional[BinaryIO] = None,
        mft: Optional[BinaryIO] = None,
        usnjrnl: Optional[BinaryIO] = None,
        sds: Optional[BinaryIO] = None,
        *args,
        **kwargs,
    ):
        super().__init__(fh, case_sensitive=False, alt_separator="\\", *args, **kwargs)
        self.ntfs = NTFS(fh, boot=boot, mft=mft, usnjrnl=usnjrnl, sds=sds)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        sector = fh.read(512)
        return sector[3:11] == NTFS_SIGNATURE

    def get(self, path: str) -> NtfsFilesystemEntry:
        return NtfsFilesystemEntry(self, path, self._get_record(path))

    def _get_record(self, path: str, root: Optional[MftRecord] = None) -> MftRecord:
        try:
            path = path.rsplit(":", maxsplit=1)[0]
            return self.ntfs.mft.get(path, root=root)
        except NtfsFileNotFoundError:
            raise FileNotFoundError(path)
        except NtfsNotADirectoryError as e:
            raise NotADirectoryError(path, cause=e)
        except NtfsError as e:
            raise FileNotFoundError(path, cause=e)


class NtfsFilesystemEntry(FilesystemEntry):
    def __init__(
        self, fs: NtfsFilesystem, path: str, entry: Optional[MftRecord] = None, index_entry: Optional[IndexEntry] = None
    ):
        super().__init__(fs, path, entry)
        self.index_entry = index_entry

        self.ads = ""
        if ":" in self.path:
            self.path, self.ads = path.rsplit(":", maxsplit=1)

    def readlink(self) -> str:
        raise NotImplementedError()

    def readlink_ext(self) -> NtfsFilesystemEntry:
        raise NotImplementedError()

    def dereference(self) -> MftRecord:
        if not self.entry:
            self.entry = self.index_entry.dereference()
        return self.entry

    def get(self, path: str) -> NtfsFilesystemEntry:
        return NtfsFilesystemEntry(
            self.fs,
            fsutil.join(self.path, path, alt_separator=self.fs.alt_separator),
            self.fs._get_record(path, self.dereference()),
        )

    def open(self, name: str = "") -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        stream = name or self.ads
        return self.dereference().open(stream)

    def _iterdir(self, ignore_dos: bool = True) -> Iterator[IndexEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self.dereference().iterdir(ignore_dos=ignore_dos):
            if entry.attribute.file_name == ".":
                continue

            yield entry

    def iterdir(self) -> Iterator[str]:
        for index_entry in self._iterdir():
            yield index_entry.attribute.file_name

    def scandir(self) -> Iterator[NtfsFilesystemEntry]:
        for index_entry in self._iterdir():
            path = fsutil.join(self.path, index_entry.attribute.file_name, alt_separator=self.fs.alt_separator)
            yield NtfsFilesystemEntry(self.fs, path, index_entry=index_entry)

    def is_dir(self) -> bool:
        return self.dereference().is_dir()

    def is_file(self) -> bool:
        return not self.is_dir()

    def is_symlink(self) -> bool:
        return False

    def stat(self) -> fsutil.stat_result:
        record = self.dereference()

        if self.is_file():
            mode = stat.S_IFREG
            try:
                size = record.size(self.ads)
            except NtfsFileNotFoundError as e:
                # Occurs when it cannot find the the specific ads inside its attributes
                raise FileNotFoundError from e
        else:
            mode = stat.S_IFDIR
            size = 0

        stdinfo = record.attributes.STANDARD_INFORMATION

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                mode | 0o777,
                record.segment,
                id(self.fs),
                record.header.ReferenceCount,
                0,
                0,
                size,
                stdinfo.last_access_time.timestamp(),
                stdinfo.last_change_time.timestamp(),
                stdinfo.creation_time.timestamp(),
            ]
        )

        # Set the nanosecond resolution separately
        st_info.st_atime_ns = stdinfo.last_access_time_ns
        st_info.st_mtime_ns = stdinfo.last_change_time_ns
        st_info.st_ctime_ns = stdinfo.creation_time_ns

        return st_info

    def lstat(self) -> fsutil.stat_result:
        return self.stat()

    def attr(self) -> AttributeMap:
        return self.dereference().attributes

    def lattr(self) -> AttributeMap:
        return self.attr()
