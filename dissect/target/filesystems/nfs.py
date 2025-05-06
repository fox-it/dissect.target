from __future__ import annotations

import stat
from functools import cached_property
from typing import TYPE_CHECKING, BinaryIO, Callable, TypeVar

from dissect.util.stream import AlignedStream

from dissect.target.exceptions import NotADirectoryError
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil
from dissect.target.helpers.nfs.client.mount import Client as MountClient
from dissect.target.helpers.nfs.client.nfs import Client as NfsClient
from dissect.target.helpers.nfs.nfs3 import (
    EntryPlus,
    FileAttributes,
    FileHandle,
    FileType,
    MountProc,
    NfsProgram,
    NfsVersion,
)
from dissect.target.helpers.sunrpc.client import AuthScheme, LocalPortPolicy, auth_null
from dissect.target.helpers.sunrpc.client import Client as SunRpcClient

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

ConCredentials = TypeVar("ConCredentials")
ConVerifier = TypeVar("ConVerifier")

ClientFactory = Callable[[], NfsClient]

# Set auth scheme programmatically, given a root filehandle and a list of supported auth flavors
# Example: Trying multiple auth schemes until one works
AuthSetter = Callable[[NfsClient, FileHandle, list[int]], None]


class AuthFlavorNotSupported(Exception):
    def __init__(self, supported_flavors: list[int], provided_flavor: int):
        self.supported = supported_flavors
        self.provided = provided_flavor

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} Auth flavor {self.provided} not supported. Supported flavors: {self.supported}"
        )


class NfsFilesystem(Filesystem):
    """Filesystem implementation of a NFS share

    The connection is lazily established to not waste resources.
    Use the ``connect`` method to conveniently create a new instance.
    """

    __type__ = "nfs"

    def __init__(self, client_factory: ClientFactory, root_handle: FileHandle):
        super().__init__()
        self._client_factory = client_factory
        self._root_handle = root_handle

    @classmethod
    def connect(
        cls,
        address: str,
        exported_dir: str,
        auth: AuthScheme[ConCredentials, ConVerifier] | AuthSetter,
        local_port: int | LocalPortPolicy = 0,
        timeout_in_seconds: float | None = 5.0,
    ) -> Self:
        """Utility function to setup a connection to a NFS share.

        Args:
            hostname: The remote hostname.
            port: The remote port.
            auth: The authentication scheme.
            local_port: The local port to bind to.
                If equal to ``LocalPortPolicy.PRIVILEGED`` or -1, bind to the first free privileged port.
                If equal to ``LocalPortPolicy.ANY`` or 0, bind to any free port.
                Otherwise, bind to the specified port.
            timeout_in_seconds: The timeout for making the connection.
        """
        with SunRpcClient.connect_port_mapper(address, timeout_in_seconds) as port_mapper_client:
            mount_port = port_mapper_client.query_port_mapping(MountProc.program, version=MountProc.version)
            nfs_port = port_mapper_client.query_port_mapping(NfsProgram, version=NfsVersion)

        # We eagerly mount the share because the root file handle is required for succesful mounting
        with MountClient.connect(address, mount_port, local_port) as mount_client:
            mount = mount_client.mount(exported_dir)

        def client_factory() -> NfsClient:
            if isinstance(auth, AuthScheme):
                if auth.flavor not in mount.auth_flavors:
                    raise AuthFlavorNotSupported(mount.auth_flavors, auth.flavor)
                return NfsClient.connect(address, nfs_port, auth, local_port)

            client = NfsClient.connect(address, nfs_port, auth_null(), local_port)
            auth(client, mount.filehandle, mount.auth_flavors)
            return client

        return NfsFilesystem(client_factory, mount.filehandle)

    @cached_property
    def _client(self) -> NfsClient:
        return self._client_factory()

    @staticmethod
    def detect(_: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on a NfsFilesystem class")  # :/

    def get(self, path: str, relentry: NfsFilesystemEntry | None = None) -> NfsFilesystemEntry:
        """Get a filesystem entry.

        Args:
            path: The path to the entry. The path is relative to ``relentry``, if provided.
            relentry: The relative entry to start from. If not provided, the root entry is used.
        """

        current_handle = relentry.entry if relentry else self._root_handle
        path = fsutil.normalize(path, self.alt_separator).strip("/")

        if not path:
            return NfsFilesystemEntry(self, "/", current_handle)

        for segment in path.split("/"):
            result = self._client.lookup(segment, current_handle)
            current_handle = result.object

        return NfsFilesystemEntry(self, path, result.object, result.obj_attributes)


class NfsFilesystemEntry(FilesystemEntry):
    fs: NfsFilesystem
    entry: FileHandle

    def __init__(self, fs: NfsFilesystem, path: str, file_handle: FileHandle, attributes: FileAttributes | None = None):
        super().__init__(fs, path, file_handle)
        self._backing_attributes = attributes

    @property
    def _attributes(self) -> FileAttributes:
        if self._backing_attributes is None:
            self._backing_attributes = self.fs._client.getattr(self.entry)
        return self._backing_attributes

    def get(self, path: str) -> NfsFilesystemEntry:
        """Get a new filesystem entry relative to this entry"""
        if not self.is_dir():
            raise NotADirectoryError

        return self.fs.get(path, relentry=self)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        # Not using _resolve since it upcasts. ("Self" from Python 3.11 would solve this)
        # Or create a subclass of Filesystementry for symlinks.
        if follow_symlinks and self.is_symlink():
            return self.readlink_ext().is_file()

        return self._attributes.type == FileType.REG

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        if follow_symlinks and self.is_symlink():
            return self.readlink_ext().is_dir()

        return self._attributes.type == FileType.DIR

    def is_symlink(self) -> bool:
        return self._attributes.type == FileType.LNK

    def readlink(self) -> str:
        return self.fs._client.readlink(self.entry)

    def readlink_ext(self) -> NfsFilesystemEntry:
        target = self.fs._client.readlink(self.entry)
        return self.fs.get(target)  # The target is an absolute path

    def _iterdir(self) -> Iterator[EntryPlus]:
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

    def _mode_file_type(self, type: FileType) -> int:
        if type == FileType.DIR:
            return stat.S_IFDIR
        if type == FileType.REG:
            return stat.S_IFREG
        if type == FileType.LNK:
            return stat.S_IFLNK
        return 0o000000


class NfsStream(AlignedStream):
    def __init__(self, client: NfsClient, file_handle: FileHandle, size: int | None):
        super().__init__(size, NfsClient.READ_CHUNK_SIZE)
        self._client = client
        self._file_handle = file_handle

    def _read(self, offset: int, size: int) -> bytes:
        data = self._client.readfile(self._file_handle, offset, size)
        return b"".join(data)
