from __future__ import annotations

import logging
import stat
from pathlib import Path
from typing import BinaryIO, Iterator

from dissect.archive import vbk

from dissect.target.exceptions import (
    NotASymlinkError,
)
from dissect.target.filesystem import (
    Filesystem,
    FilesystemEntry,
    VirtualFilesystem, )
from dissect.target.helpers import fsutil

log = logging.getLogger(__name__)


class VBKFilesystem(Filesystem):
    """Filesystem implementation for VBK files.
    """

    __type__ = "vbk"

    def __init__(
            self,
            fh: BinaryIO,
            *args,
            **kwargs,
    ):
        super().__init__(fh, *args, **kwargs)

        self.vbk = vbk.VBK(fh)
        self._fs = VirtualFilesystem(alt_separator=self.alt_separator, case_sensitive=self.case_sensitive)

        def map_entries(directory, parent_path) -> None:
            for entry in directory.iterdir():
                entry_path = parent_path.joinpath(entry.name)
                if entry.is_dir():
                    map_entries(entry, entry_path)
                else:
                    self._fs.map_file_entry(entry_path.__str__(), VBKFilesystemEntry(self, str(entry_path), entry))

        map_entries(self.vbk.get("/"), Path("/"))

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on VBKFilesystem class")

    def get(self, path: str, relentry: FilesystemEntry = None) -> FilesystemEntry:
        """Returns a VBKFilesystemEntry object corresponding to the given path."""
        return self._fs.get(path, relentry=relentry)


class VBKFilesystemEntry(FilesystemEntry):
    fs: VBKFilesystem
    entry: vbk.MetaItem

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(fsutil.join(self.path, path, alt_separator=self.fs.alt_separator))

    def iterdir(self) -> Iterator[str]:
        return self.entry.iterdir()

    def scandir(self) -> Iterator[FilesystemEntry]:
        return self.entry.iterdir()

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

        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        st_info = [
            mode | 0o755,
            fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator),
            id(self.fs),
            1,
            0,
            0,
            self.entry.size,
            0,
            0,
            0,
        ]
        return fsutil.stat_result(st_info)
