from __future__ import annotations

import stat
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.ese import ESE
from dissect.database.ese.c_ese import ulDAEMagic
from dissect.database.ese.ntds import NTDS, Object

from dissect.target.exceptions import FileNotFoundError, NotASymlinkError
from dissect.target.filesystem import DirEntry, Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator


class NtdsFilesystem(Filesystem):
    """Filesystem implementation for NTDS.dit files. Because we can."""

    __type__ = "ntds"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        self.ntds = NTDS(fh)
        super().__init__(fh, *args, case_sensitive=False, **kwargs)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        buf = fh.read(8)
        if int.from_bytes(buf[4:8], "little") == ulDAEMagic:
            ese = ESE(fh)
            return {"datatable", "link_table"}.issubset(table.name for table in ese.tables())
        return False

    def get(self, path: str) -> NtdsFilesystemEntry:
        return NtdsFilesystemEntry(self, path, self._get_object(path))

    def _get_object(self, path: str, root: Object | None = None) -> Object:
        obj = root or self.ntds.root()

        for part in path.split("/"):
            if not part or part == ".":
                continue

            if part == "..":
                if obj.parent() is None:
                    continue
                obj = obj.parent()
            else:
                for child in obj.children():
                    if child.name == part:
                        obj = child
                        break
                else:
                    raise FileNotFoundError(f"Path not found: {path}")

        return obj


class NtdsDirEntry(DirEntry):
    entry: Object

    def get(self) -> NtdsFilesystemEntry:
        return NtdsFilesystemEntry(self.fs, self.path, self.entry)

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        return next(self.entry.children(), None) is not None

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        return True

    def is_symlink(self) -> bool:
        return False

    def stat(self, *, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class NtdsFilesystemEntry(FilesystemEntry):
    fs: NtdsFilesystem
    entry: Object

    def get(self, path: str) -> NtdsFilesystemEntry:
        return NtdsFilesystemEntry(
            self.fs,
            fsutil.join(self.path, path, alt_separator=self.fs.alt_separator),
            self.fs._get_object(path, self.entry),
        )

    def open(self) -> BinaryIO:
        info = "\n".join(f"{key}: {value}" for key, value in self.entry.as_dict().items())
        return BytesIO(info.encode())

    def scandir(self) -> Iterator[NtdsDirEntry]:
        for child in self.entry.children():
            yield NtdsDirEntry(self.fs, self.path, child.name, child)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return next(self.entry.children(), None) is not None

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return True

    def is_symlink(self) -> bool:
        return False

    def readlink(self) -> str:
        raise NotASymlinkError(self.path)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        mode = stat.S_IFDIR if self.is_dir() else stat.S_IFREG

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        return fsutil.stat_result(
            [
                mode | 0o777,
                self.entry.dnt,
                id(self.fs),
                1,
                0,
                0,
                0,
                0,
                self.entry.when_changed.timestamp() if self.entry.when_changed else 0,
                self.entry.when_created.timestamp() if self.entry.when_created else 0,
            ]
        )
