from __future__ import annotations

import stat
from functools import cached_property
from typing import BinaryIO, Callable, Iterator

from dissect.util.stream import AlignedStream

from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil
from dissect.target.helpers.nfs.client.nfs import Client
from dissect.target.helpers.nfs.nfs3 import (
    EntryPlus3,
    FileAttributes3,
    FileHandle3,
    FileType3,
)

ClientFactory = Callable[[], Client]


class NfsFilesystem(Filesystem):
    """Filesystem implementation of a NFS share

    The client is lazily constructed
    """

    __type__ = "nfs"

    def __init__(self, client_factory: ClientFactory, root_handle: FileHandle3):
        super().__init__()
        self._client_factory = client_factory
        self._backing_client = None
        self._root_handle = root_handle

    @cached_property
    def _client(self) -> Client:
        return self._client_factory()

    @staticmethod
    def detect(_: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on a NfsFilesystem class")  # :/

    def get(self, path: str) -> NfsFilesystemEntry:
        path = fsutil.normalize(path, self.alt_separator).strip("/")

        if not path:
            return NfsFilesystemEntry(self, "/", self._root_handle)

        current_handle = self._root_handle
        for segment in path.split("/"):
            result = self._client.lookup(segment, current_handle)
            current_handle = result.object

        return NfsFilesystemEntry(self, path, result.object, result.obj_attributes)


class NfsFilesystemEntry(FilesystemEntry):
    fs: NfsFilesystem
    entry: FileHandle3

    def __init__(
        self, fs: NfsFilesystem, path: str, file_handle: FileHandle3, attributes: FileAttributes3 | None = None
    ):
        super().__init__(fs, path, file_handle)
        self._backing_attributes = attributes

    @property
    def _attributes(self) -> FileAttributes3:
        if self._backing_attributes is None:
            self._backing_attributes = self.fs._client.getattr(self.entry)
        return self._backing_attributes

    def get(self, path: str) -> NfsFilesystemEntry:
        path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return self.fs.get(path)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        # Not using _resolve since it upcasts. ("Self" from Python 3.11 would solve this)
        # Or create a subclass of Filesystementry for symlinks.
        if follow_symlinks and self.is_symlink():
            return self.readlink_ext().is_file()

        return self._attributes.type == FileType3.REG

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        if follow_symlinks and self.is_symlink():
            return self.readlink_ext().is_dir()

        return self._attributes.type == FileType3.DIR

    def is_symlink(self) -> bool:
        return self._attributes.type == FileType3.LNK

    def readlink(self) -> str:
        return self.fs._client.readlink(self.entry)

    def readlink_ext(self) -> NfsFilesystemEntry:
        target = self.fs._client.readlink(self.entry)
        return self.get(target)

    def _iterdir(self) -> Iterator[EntryPlus3]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        yield from self.fs._client.readdir(self.entry).entries

    def iterdir(self) -> Iterator[str]:
        for entry in self._iterdir():
            yield entry.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        for entry in self._iterdir():
            yield NfsFilesystemEntry(self.fs, entry.name, entry.handle, entry.attributes)

    def open(self) -> NfsStream:
        # Pass size if available but don't sweat it
        size = self._backing_attributes.size if self._backing_attributes else None
        return NfsStream(self.fs._client, self.entry, size)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        if follow_symlinks and self.is_symlink():
            return self.readlink_ext().lstat()

        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        attributes = self._attributes

        st_info = fsutil.stat_result(
            [
                attributes.mode | self._mode_file_type(attributes.type),
                fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator),
                attributes.fsid,
                attributes.nlink,
                attributes.uid,
                attributes.gid,
                attributes.size,
                attributes.atime.seconds,
                attributes.mtime.seconds,
                attributes.ctime.seconds,
            ]
        )

        st_info.st_atime_ns = attributes.atime.nseconds
        st_info.st_mtime_ns = attributes.mtime.nseconds
        st_info.st_ctime_ns = attributes.ctime.nseconds

        return st_info

    def _mode_file_type(self, type: FileType3) -> int:
        if type == FileType3.DIR:
            return stat.S_IFDIR
        elif type == FileType3.REG:
            return stat.S_IFREG
        elif type == FileType3.LNK:
            return stat.S_IFLNK
        else:
            return 0o000000


class NfsStream(AlignedStream):
    def __init__(self, client: Client, file_handle: FileHandle3, size: int | None):
        super().__init__(size, Client.READ_CHUNK_SIZE)
        self._client = client
        self._file_handle = file_handle

    def _read(self, offset, size: int) -> bytes:
        data = self._client.readfile(self._file_handle, offset, size)
        return b"".join(data)
