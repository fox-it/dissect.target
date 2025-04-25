from __future__ import annotations

import stat
from typing import TYPE_CHECKING, BinaryIO

from dissect.archive import vbk

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import (
    Filesystem,
    FilesystemEntry,
)
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator


class VbkFilesystem(Filesystem):
    """Filesystem implementation for VBK files."""

    __type__ = "vbk"

    def __init__(self, fh: BinaryIO, *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.vbk = vbk.VBK(fh)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        try:
            vbk.VBK(fh)
        except vbk.VBKError:
            return False
        else:
            return True

    def get(self, path: str) -> FilesystemEntry:
        return VbkFilesystemEntry(self, path, self._get_node(path))

    def _get_node(self, path: str, node: vbk.DirItem | None = None) -> FilesystemEntry:
        try:
            return self.vbk.get(path, node)
        except vbk.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except vbk.IsADirectoryError as e:
            raise IsADirectoryError(path) from e
        except vbk.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except vbk.Error as e:
            raise FilesystemError(path) from e


class VbkFilesystemEntry(FilesystemEntry):
    fs: VbkFilesystem
    entry: vbk.DirItem

    def get(self, path: str) -> FilesystemEntry:
        return VbkFilesystemEntry(
            self.fs,
            fsutil.join(self.path, path, alt_separator=self.fs.alt_separator),
            self.fs._get_node(path, self.entry),
        )

    def open(self) -> None:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.entry.open()

    def iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self.entry.iterdir():
            yield entry.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self.entry.iterdir():
            yield VbkFilesystemEntry(
                self.fs,
                fsutil.join(self.path, entry.name, alt_separator=self.fs.alt_separator),
                entry,
            )

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return self.entry.is_dir()

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return self.entry.is_file()

    def is_symlink(self) -> bool:
        return False

    def readlink(self) -> str:
        raise NotASymlinkError

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.lstat()

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
