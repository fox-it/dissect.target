from __future__ import annotations

import stat
from typing import BinaryIO, Iterator

from dissect.archive import vbk

from dissect.target.exceptions import (
    NotASymlinkError,
)
from dissect.target.filesystem import (
    Filesystem,
    FilesystemEntry,
)
from dissect.target.helpers import fsutil


class VbkFilesystem(Filesystem):
    """Filesystem implementation for VBK files."""

    __type__ = "vbk"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)

        self.vbk = vbk.VBK(fh)
        self._fs = None

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        try:
            vbk.VBK(fh)
            return True
        except vbk.VBKError:
            return False

    def get(self, path: str, relentry: FilesystemEntry = None) -> FilesystemEntry:
        return VbkFilesystemEntry(self, path, self.vbk.get(path))


class VbkFilesystemEntry(FilesystemEntry):
    fs: VbkFilesystem
    entry: vbk.MetaItem

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(fsutil.join(self.path, path, alt_separator=self.fs.alt_separator))

    def iterdir(self) -> Iterator[str]:
        for entry in self.entry.iterdir():
            yield entry.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        for entry in self.entry.iterdir():
            path = fsutil.join(self.path, entry.name)
            yield VbkFilesystemEntry(self.fs, path, entry)

    def open(self) -> None:
        return self.entry.open()

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return self.entry.is_dir()

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return self.entry.is_file()

    def is_symlink(self) -> bool:
        return False

    def readlink(self) -> str:
        raise NotASymlinkError()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        mode = stat.S_IFDIR if self.is_dir() else stat.S_IFREG
        size = 0 if self.is_dir() else self.entry.size

        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        st_info = [
            mode | 0o755,
            fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator),
            id(self.fs),
            1,
            0,
            0,
            size,
            0,
            0,
            0,
        ]
        return fsutil.stat_result(st_info)
