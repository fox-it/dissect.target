from __future__ import annotations

import stat
from datetime import timedelta, timezone
from typing import TYPE_CHECKING, BinaryIO, Optional

from dissect.fat import exfat
from dissect.util.stream import RunlistStream
from dissect.util.ts import dostimestamp

from dissect.target.exceptions import FileNotFoundError, NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator

ExfatFileTree = tuple[exfat.c_exfat.FILE, dict[str, Optional["ExfatFileTree"]]]


class ExfatFilesystem(Filesystem):
    __type__ = "exfat"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, case_sensitive=False, alt_separator="\\", **kwargs)
        self.exfat = exfat.ExFAT(fh)
        self.cluster_size = self.exfat.cluster_size

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return fh.read(11)[3:] == b"EXFAT   "

    def get(self, path: str) -> ExfatFilesystemEntry:
        return ExfatFilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(self, path: str, root: ExfatFileTree | None = None) -> ExfatFileTree:
        dirent = root if root is not None else self.exfat.files["/"]

        # Programmatically we will often use the `/` separator, so replace it
        # with the native path separator of exFAT `/` is an illegal character
        # in exFAT filenames, so it's safe to replace
        parts = path.replace("/", "\\").split("\\")

        for part in parts:
            if not part:
                continue

            file_tree = dirent[1]
            if file_tree is None:
                raise NotADirectoryError(f"Not a directory: {path}")

            for entry_name, entry_file_tree in file_tree.items():
                if entry_name.upper() == part.upper():
                    dirent = entry_file_tree
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return dirent


class ExfatFilesystemEntry(FilesystemEntry):
    def __init__(
        self,
        fs: ExfatFilesystem,
        path: str,
        entry: ExfatFileTree,
    ):
        super().__init__(fs, path, entry)
        self.size = self.entry[0].stream.data_length
        self.cluster = self.entry[0].stream.location

    def get(self, path: str) -> ExfatFilesystemEntry:
        """Get a filesystem entry relative from the current one."""
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return ExfatFilesystemEntry(self.fs, full_path, self.fs._get_entry(path, self.entry))

    def open(self) -> BinaryIO:
        if self.entry[0].stream.flags.not_fragmented:
            runlist = self.fs.exfat.runlist(self.cluster, True, self.size)
        else:
            runlist = self.fs.exfat.runlist(self.cluster, False)
        return RunlistStream(self.fs.exfat.filesystem, runlist, self.size, self.fs.cluster_size)

    def _iterdir(self) -> Iterator[tuple[str, ExfatFileTree]]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry_name, entry_file_tree in self.entry[1].items():
            if entry_name in (".", ".."):
                continue
            yield (entry_name, entry_file_tree)

    def iterdir(self) -> Iterator[str]:
        """List the directory contents of a directory. Returns a generator of strings."""
        for entry_name, _ in self._iterdir():
            yield entry_name

    def scandir(self) -> Iterator[ExfatFilesystemEntry]:
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        for entry_name, entry_file_tree in self._iterdir():
            path = fsutil.join(self.path, entry_name, alt_separator=self.fs.alt_separator)
            yield ExfatFilesystemEntry(self.fs, path, entry_file_tree)

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return False

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a directory."""
        return bool(self.entry[0].metadata.attributes.directory)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a file."""
        return not self.is_dir()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        fe = self.entry[0]
        size = fe.stream.data_length
        addr = fe.stream.location

        # exfat stores additional offsets for ctime and mtime to get 10 millisecond precision
        fe = fe.metadata

        # all timestamps are recorded in local time. the utc offset (of the system generating the timestamp in question)
        # is recorded in the associated tz byte
        c_tz = self.fs.exfat._utc_timezone(fe.create_timezone)
        c_tzinfo = timezone(timedelta(minutes=c_tz["offset"]), c_tz["name"])
        m_tz = self.fs.exfat._utc_timezone(fe.modified_timezone)
        m_tzinfo = timezone(timedelta(minutes=m_tz["offset"]), m_tz["name"])
        a_tz = self.fs.exfat._utc_timezone(fe.access_timezone)
        a_tzinfo = timezone(timedelta(minutes=a_tz["offset"]), a_tz["name"])

        ctime = dostimestamp(fe.create_time, fe.create_offset).replace(tzinfo=c_tzinfo)
        mtime = dostimestamp(fe.modified_time, fe.modified_offset).replace(tzinfo=m_tzinfo)
        atime = dostimestamp(fe.access_time).replace(tzinfo=a_tzinfo)

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = [
            (stat.S_IFDIR if self.is_dir() else stat.S_IFREG) | 0o777,
            addr,
            id(self.fs),
            0,
            0,
            0,
            size,
            atime.timestamp(),
            mtime.timestamp(),
            ctime.timestamp(),
        ]
        return fsutil.stat_result(st_info)
