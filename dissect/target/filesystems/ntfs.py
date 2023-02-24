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
    NotASymlinkError,
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

        if self.is_symlink():
            return self.readlink_ext().open(name)

        stream = name or self.ads
        return self.dereference().open(stream)

    def _iterdir(self, ignore_dos: bool = True) -> Iterator[IndexEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext()._iterdir(ignore_dos=ignore_dos)
            return

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
        return self.dereference().is_reparse_point()

    def readlink(self) -> str:
        # Note: we only need to check and resolve symlinks when actually interacting with the target, such as
        # opening a file or iterating a directory. This is because the reparse point itself will have the appropriate
        # flags set to indicate if the target is a file or directory
        if not self.is_symlink():
            raise NotASymlinkError()

        reparse_point = self.dereference().attributes.REPARSE_POINT
        print_name = reparse_point.print_name
        if reparse_point.absolute:
            # Prefix with \\ to make the path play ball with all the filesystem utilities
            # Note: absolute links (such as directory junctions) will _always_ fail within the filesystem
            # This is because absolute links include the drive letter, of which we have no knowledge here
            # These will only work in the RootFilesystem
            print_name = "\\" + print_name
        return fsutil.normalize(print_name, self.fs.alt_separator)

    def stat(self) -> fsutil.stat_result:
        if self.is_symlink():
            return self.readlink_ext().lstat()
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        record = self.dereference()

        size = 0
        if self.is_symlink():
            mode = stat.S_IFLNK
        elif self.is_file():
            mode = stat.S_IFREG
            try:
                size = record.size(self.ads)
            except NtfsFileNotFoundError as e:
                # Occurs when it cannot find the the specific ads inside its attributes
                raise FileNotFoundError from e
        else:
            mode = stat.S_IFDIR

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

    def attr(self) -> AttributeMap:
        if self.is_symlink():
            return self.readlink_ext().lattr()
        return self.lattr()

    def lattr(self) -> AttributeMap:
        return self.dereference().attributes
