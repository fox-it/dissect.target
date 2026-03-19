from __future__ import annotations

import stat
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence import ad1

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import DirEntry, Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil, keychain

if TYPE_CHECKING:
    from collections.abc import Iterator


class AD1Filesystem(Filesystem):
    __type__ = "ad1"

    def __init__(self, fh: BinaryIO | list[BinaryIO] | Path | list[Path], *args, **kwargs):
        super().__init__(fh, *args, **kwargs)
        self.ad1 = ad1.AD1(fh)

        if self.ad1.is_adcrypt():
            keys = keychain.get_keys_for_provider(self.__type__) + keychain.get_keys_without_provider()

            if not keys:
                raise ValueError("Failed to unlock ADCRYPT: no key(s) provided")

            for key in keys:
                try:
                    if key.key_type == keychain.KeyType.PASSPHRASE:
                        self.ad1.unlock(passphrase=key.value)
                    elif key.key_type == keychain.KeyType.FILE and (path := Path(key.value)).is_file():
                        self.ad1.unlock(private_key=path)
                except ValueError:  # noqa: PERF203
                    pass

            if self.ad1.is_locked():
                raise ValueError("Failed to unlock ADCRYPT using provided key(s)")

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        return fh.read(16) == b"ADSEGMENTEDFILE\x00"

    def get(self, path: str) -> FilesystemEntry:
        return AD1FilesystemEntry(self, path, self._get_entry(path))

    def _get_entry(self, path: str, entry: ad1.FileEntry | None = None) -> ad1.FileEntry:
        try:
            return self.ad1.entry(path, entry)
        except ad1.FileNotFoundError as e:
            raise FileNotFoundError(path) from e
        except ad1.NotADirectoryError as e:
            raise NotADirectoryError(path) from e
        except ad1.NotASymlinkError as e:
            raise NotASymlinkError(path) from e
        except ad1.Error as e:
            raise FileNotFoundError(path) from e


class AD1DirEntry(DirEntry):
    fs: AD1Filesystem
    entry: ad1.FileEntry

    def get(self) -> AD1FilesystemEntry:
        return AD1FilesystemEntry(self.fs, self.path, self.entry)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.get().stat(follow_symlinks=follow_symlinks)


class AD1FilesystemEntry(FilesystemEntry):
    fs: AD1Filesystem
    entry: ad1.FileEntry

    def get(self, path: str) -> FilesystemEntry:
        entry_path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        entry = self.fs._get_entry(path, self.entry)
        return AD1FilesystemEntry(self.fs, entry_path, entry)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.entry.open()

    def scandir(self) -> Iterator[AD1DirEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        for entry in self.entry.iterdir():
            yield AD1DirEntry(self.fs, self.path, entry.name, entry)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.is_symlink()

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError(self.path)
        return self.entry.readlink()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        if self.is_symlink():
            mode = stat.S_IFLNK
        elif self.is_file():
            mode = stat.S_IFREG
        else:
            mode = stat.S_IFDIR

        st_info = fsutil.stat_result(
            [
                mode | 0o777,
                self.entry.offset,
                id(self.fs),
                1,  # nlink
                0,  # uid
                0,  # gid
                self.entry.size,
                self.entry.atime.timestamp(),
                self.entry.mtime.timestamp(),
                self.entry.ctime.timestamp(),
            ]
        )

        st_info.st_birthtime = self.entry.btime.timestamp()
        return st_info
