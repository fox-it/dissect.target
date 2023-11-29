import datetime
import stat
from typing import BinaryIO, Iterator, Optional, Union

from dissect.fat import exceptions as fat_exc
from dissect.fat import fat

from dissect.target.exceptions import FileNotFoundError, NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil


class FatFilesystem(Filesystem):
    __type__ = "fat"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, case_sensitive=False, alt_separator="\\", *args, **kwargs)
        self.fatfs = fat.FATFS(fh)
        # FAT timestamps are in local time, so to prevent skewing them even more, we specify UTC by default.
        # However, it should be noted that they are not actual UTC timestamps!
        # Implementers can optionally set the tzinfo attribute of this class to get correct UTC timestamps.
        self.tzinfo = datetime.timezone.utc

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect a FAT filesystem on a given file-like object."""
        try:
            fat.validate_bpb(fh.read(512))
            return True
        except fat_exc.InvalidBPB:
            return False

    def get(self, path: str) -> FilesystemEntry:
        """Returns a FatFilesystemEntry object corresponding to the given pathname"""
        return FatFilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(
        self, path: str, entry: Optional[Union[fat.RootDirectory, fat.DirectoryEntry]] = None
    ) -> Union[fat.RootDirectory, fat.DirectoryEntry]:
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
    def get(self, path: str) -> FilesystemEntry:
        """Get a filesystem entry relative from the current one."""
        full_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return FatFilesystemEntry(self.fs, full_path, self.fs._get_entry(path, self.entry))

    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.entry.open()

    def iterdir(self) -> Iterator[str]:
        """List the directory contents of a directory. Returns a generator of strings."""
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for f in self.entry.iterdir():
            if f.name in (".", ".."):
                continue
            yield f.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        """List the directory contents of this directory. Returns a generator of filesystem entries."""
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for f in self.entry.iterdir():
            if f.name in (".", ".."):
                continue
            path = fsutil.join(self.path, f.name, alt_separator=self.fs.alt_separator)
            yield FatFilesystemEntry(self.fs, path, f)

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return False

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a directory."""
        return self.entry.is_directory()

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a file."""
        return not self.is_dir()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = [
            (stat.S_IFDIR if self.is_dir() else stat.S_IFREG) | 0o777,
            self.entry.cluster,
            id(self.fs),
            1,
            0,
            0,
            self.entry.size,
            self.entry.atime.replace(tzinfo=self.fs.tzinfo).timestamp(),
            self.entry.mtime.replace(tzinfo=self.fs.tzinfo).timestamp(),
            self.entry.ctime.replace(tzinfo=self.fs.tzinfo).timestamp(),
        ]
        return fsutil.stat_result(st_info)
