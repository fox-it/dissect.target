from __future__ import annotations

from typing import BinaryIO, Iterator
from dissect.target.exceptions import NotASymlinkError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil
from dissect.target.helpers.nfs.client import Client
from dissect.target.helpers.nfs.nfs3 import EntryPlus3, FileAttributes3, FileHandle3, FileType3
from dissect.util.stream import AlignedStream


class NfsFilesystem(Filesystem):
    __type__ = "nfs"

    def __init__(self, client: Client, root_handle: FileHandle3):
        super().__init__()
        self._client = client
        self._root_handle = root_handle

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
    def __init__(
        self, fs: NfsFilesystem, path: str, file_handle: FileHandle3, attributes: FileAttributes3 | None = None
    ):
        super().__init__(fs, path, file_handle)
        self._fs = fs
        self._file_handle = file_handle
        self._lazy_attributes = attributes

    @property
    def _attributes(self) -> FileAttributes3:
        if self._lazy_attributes is None:
            self._lazy_attributes = self._fs._client.getattr(self._file_handle)
        return self._lazy_attributes

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(fsutil.join(self.path, path, alt_separator=self.fs.alt_separator))

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return self._attributes.type == FileType3.REG

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return self._attributes.type == FileType3.DIR

    def is_symlink(self) -> bool:
        return self._attributes.type == FileType3.LNK

    def readlink(self) -> str:
        raise NotASymlinkError()

    def _iterdir(self) -> Iterator[EntryPlus3]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        # Symlink ?

        yield from self._fs._client.readdir(self._file_handle).entries

    def iterdir(self) -> Iterator[str]:
        """Iterate over the contents of a directory, return them as strings.

        Returns:
            An iterator of directory entries as path strings.
        """

        for entry in self._iterdir():
            if entry.name not in (".", ".."):
                yield entry.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        """Iterate over the contents of a directory, yields :class:`FilesystemEntry`.

        Returns:
            An iterator of :class:`FilesystemEntry`.
        """

        for entry in self._iterdir():
            yield NfsFilesystemEntry(self.fs, entry.name, entry.handle, entry.attributes)

    def open(self) -> NfsStream:
        return NfsStream(self._fs._client, self._file_handle)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        # return self._resolve(follow_symlinks=follow_symlinks).lstat()
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        attributes = self._attributes

        st_info = [
            attributes.mode,
            fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator),
            attributes.fsid,
            attributes.nlink,
            attributes.uid,
            attributes.gid,
            attributes.size,
            attributes.atime,
            attributes.mtime,
            attributes.ctime,
        ]

        return fsutil.stat_result(st_info)


class NfsStream(AlignedStream):
    def __init__(self, client: Client, file_handle: FileHandle3):
        super().__init__(None, Client.READ_CHUNK_SIZE)
        self._client = client
        self._file_handle = file_handle

    def _read(self, offset, size: int) -> bytes:
        data = self._client.readfile(self._file_handle, offset, size)
        return b"".join(data)
