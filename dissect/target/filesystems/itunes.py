from __future__ import annotations

import stat
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream

from dissect.target.exceptions import FilesystemError, NotASymlinkError
from dissect.target.filesystem import (
    Filesystem,
    FilesystemEntry,
    VirtualDirectory,
    VirtualFile,
    VirtualFilesystem,
)
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.loaders.itunes import FileInfo, ITunesBackup


class ITunesFilesystem(Filesystem):
    """Filesystem implementation for iTunes backups."""

    __type__ = "itunes"

    def __init__(self, backup: ITunesBackup, *args, **kwargs):
        super().__init__(None, *args, **kwargs)
        self.backup = backup

        self._fs = VirtualFilesystem(alt_separator=self.alt_separator, case_sensitive=self.case_sensitive)

        for file in self.backup.files():
            entry_cls = (
                ITunesFilesystemDirectoryEntry if stat.S_IFMT(file.mode) == stat.S_IFDIR else ITunesFilesystemEntry
            )

            file_entry = entry_cls(self, file.translated_path, file)
            self._fs.map_file_entry(file.translated_path, file_entry)

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on ITunesFilesystem class")

    def get(self, path: str, relentry: FilesystemEntry | None = None) -> FilesystemEntry:
        """Returns a ITunesFileEntry object corresponding to the given path."""
        return self._fs.get(path, relentry)


class ITunesFilesystemEntry(VirtualFile):
    def open(self) -> BinaryIO:
        """Returns file handle (file-like object)."""
        if self.is_dir():
            raise IsADirectoryError(self.path)

        if self.entry.backup.encrypted:
            return EncryptedFileStream(self.entry)
        return self.entry.get().open("rb")

    def iterdir(self) -> Iterator[str]:
        if self.is_dir():
            return self._resolve().iterdir()
        return super().iterdir()

    def scandir(self) -> Iterator[FilesystemEntry]:
        if self.is_dir():
            return self._resolve().scandir()
        return super().scandir()

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a directory."""
        try:
            return stat.S_IFMT(self._resolve(follow_symlinks=follow_symlinks).entry.mode) == stat.S_IFDIR
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Return whether this entry is a file."""
        try:
            return stat.S_IFMT(self._resolve(follow_symlinks=follow_symlinks).entry.mode) == stat.S_IFREG
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        """Return whether this entry is a link."""
        return stat.S_IFMT(self.entry.mode) == stat.S_IFLNK

    def readlink(self) -> str:
        """Read the link if this entry is a symlink. Returns a string."""
        if not self.is_symlink():
            raise NotASymlinkError
        return self.entry.metadata["Target"]

    def readlink_ext(self) -> FilesystemEntry:
        """Read the link if this entry is a symlink. Returns a filesystem entry."""
        # Can't use the one in VirtualFile as it overrides the FilesystemEntry
        return fsutil.resolve_link(self.fs, self.readlink(), self.path, alt_separator=self.fs.alt_separator)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        metadata = self.entry.metadata
        # ['mode', 'addr', 'dev', 'nlink', 'uid', 'gid', 'size', 'atime', 'mtime', 'ctime']
        return fsutil.stat_result(
            [
                metadata["Mode"],
                metadata["InodeNumber"],
                id(self.fs),
                1,
                metadata["UserID"],
                metadata["GroupID"],
                metadata["Size"],
                0,
                metadata["LastModified"],
                metadata["Birth"],
            ]
        )


class ITunesFilesystemDirectoryEntry(VirtualDirectory):
    def __init__(self, fs: Filesystem, path: str, entry: FileInfo):
        super().__init__(fs, path)
        self.entry = entry

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Return the stat information of this entry."""
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        """Return the stat information of the given path, without resolving links."""
        metadata = self.entry.metadata
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        return fsutil.stat_result(
            [
                metadata["Mode"],
                metadata["InodeNumber"],
                id(self.fs),
                0,
                metadata["UserID"],
                metadata["GroupID"],
                metadata["Size"],
                0,
                metadata["LastModified"],
                metadata["Birth"],
            ]
        )


class EncryptedFileStream(AlignedStream):
    """Transparently decrypted AES-CBC decrypted stream."""

    def __init__(self, file_info: FileInfo):
        super().__init__(file_info.size)
        self.file_info = file_info
        self.fh = file_info.get().open("rb")

        self.cipher = None
        self.cipher_offset = 0

        self._reset_cipher()

    def _reset_cipher(self) -> None:
        self.cipher = self.file_info.create_cipher()
        self.cipher_offset = 0

    def _seek_cipher(self, offset: int) -> None:
        """CBC is dependent on previous blocks so to seek the cipher, decrypt and discard to the wanted offset."""
        if offset < self.cipher_offset:
            self._reset_cipher()
            self.fh.seek(0)

        while self.cipher_offset < offset:
            read_size = min(offset - self.cipher_offset, self.align)
            self.cipher.decrypt(self.fh.read(read_size))
            self.cipher_offset += read_size

    def _read(self, offset: int, length: int) -> bytes:
        self._seek_cipher(offset)

        data = self.cipher.decrypt(self.fh.read(length))
        self.cipher_offset += length

        return data
