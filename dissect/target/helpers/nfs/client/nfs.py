from __future__ import annotations

from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, NamedTuple, TypeVar

from dissect.target.exceptions import Error
from dissect.target.helpers.nfs.nfs3 import (
    CookieVerf,
    DirOpArgs,
    EntryPlus,
    FileAttributes,
    FileHandle,
    GetAttrProc,
    LookupProc,
    LookupResult,
    NfsStat,
    ReadDirPlusParams,
    ReadDirPlusProc,
    ReadFileProc,
    ReadLinkProc,
    ReadParams,
)
from dissect.target.helpers.nfs.serializer import (
    DirOpArgs3Serializer,
    FileAttributesSerializer,
    Lookup3ResultDeserializer,
    Read3ArgsSerializer,
    Read3ResultDeserializer,
    ReadDirPlusParamsSerializer,
    ReadDirPlusResultDeserializer,
    ReadLink3ResultDeserializer,
)
from dissect.target.helpers.nfs.serializer import (
    ResultDeserializer as NfsResultDeserializer,
)
from dissect.target.helpers.sunrpc.client import AbstractClient as SunRpcAbstractClient
from dissect.target.helpers.sunrpc.client import AuthScheme, LocalPortPolicy
from dissect.target.helpers.sunrpc.client import Client as SunRpcClient
from dissect.target.helpers.sunrpc.serializer import OpaqueVarLengthSerializer

if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from typing_extensions import Self

Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")


class NfsError(Error):
    def __init__(self, message: str, nfsstat: NfsStat):
        super().__init__(message)
        self.message = message
        self.nfsstat = nfsstat

    def __str__(self) -> str:
        return f"{self.__class__.__name__} (NfsStat: {self.nfsstat}): {self.message}"


class ReadDirResult(NamedTuple):
    dir_attributes: FileAttributes | None
    entries: list[EntryPlus]


class Client(AbstractContextManager):
    DIR_COUNT = 4096  # See https://datatracker.ietf.org/doc/html/rfc1813#section-3.3.17
    MAX_COUNT = 32768
    READ_CHUNK_SIZE = 1024 * 1024

    def __init__(self, rpc_client: SunRpcAbstractClient):
        self._rpc_client = rpc_client

    def __enter__(self) -> Self:
        """Return ``self`` upon entering the runtime context."""
        return self  # type: Necessary for type checker

    def __exit__(self, _: type[BaseException] | None, __: BaseException | None, ___: TracebackType | None) -> bool:
        self.close()
        return False  # Reraise exceptions

    @classmethod
    def connect(
        cls,
        hostname: str,
        port: int,
        auth: AuthScheme[Credentials, Verifier],
        local_port: int | LocalPortPolicy = 0,
        timeout_in_seconds: float | None = 5.0,
    ) -> Client:
        """Connect to a NFS server.

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

        rpc_client = SunRpcClient.connect(hostname, port, auth, local_port, timeout_in_seconds)
        return Client(rpc_client)

    def rebind_auth(self, auth: AuthScheme[Credentials, Verifier]) -> None:
        """Change the authentication scheme of the underlying sunrpc client."""

        self._rpc_client = self._rpc_client.rebind_auth(auth)

    def readdir(self, dir: FileHandle) -> ReadDirResult | NfsStat:
        """Read the contents of a directory, including file attributes."""

        entries = list[EntryPlus]()
        cookie = 0
        cookieverf = CookieVerf(b"\x00")
        read_deserializer = NfsResultDeserializer(ReadDirPlusResultDeserializer())

        # Multiple calls might be needed to read the entire directory
        while True:
            args = ReadDirPlusParams(dir, cookie, cookieverf, dir_count=self.DIR_COUNT, max_count=self.MAX_COUNT)

            result = self._rpc_client.call(ReadDirPlusProc, args, ReadDirPlusParamsSerializer(), read_deserializer)
            if isinstance(result, NfsStat):
                raise NfsError("Failed to read dir", result)

            entries += result.entries
            if result.eof or len(result.entries) == 0:
                return ReadDirResult(result.dir_attributes, entries)

            cookie = result.entries[-1].cookie
            cookieverf = result.cookieverf

    def readfile(self, handle: FileHandle, offset: int = 0, size: int = -1) -> Iterator[bytes]:
        """Read a file by its file handle."""
        bytes_left = size
        read_deserializer = NfsResultDeserializer(Read3ResultDeserializer())
        while size == -1 or bytes_left > 0:
            count = self.READ_CHUNK_SIZE if size == -1 else min(self.READ_CHUNK_SIZE, size)
            params = ReadParams(handle, offset, count)
            result = self._rpc_client.call(ReadFileProc, params, Read3ArgsSerializer(), read_deserializer)
            if isinstance(result, NfsStat):
                raise NfsError("Failed to read file", result)
            yield result.data
            if result.eof:
                return
            offset += result.count
            bytes_left -= result.count

    def lookup(self, name: str, parent: FileHandle) -> LookupResult:
        """Lookup a file by name in a directory."""

        args = DirOpArgs(parent, name)
        lookup_deserializer = NfsResultDeserializer(Lookup3ResultDeserializer())
        result = self._rpc_client.call(LookupProc, args, DirOpArgs3Serializer(), lookup_deserializer)
        if isinstance(result, NfsStat):
            raise NfsError("Failed to lookup file", result)

        return result

    def getattr(self, handle: FileHandle) -> FileAttributes:
        """Get the attributes of a file by its file handle."""

        attr_deserializer = NfsResultDeserializer(FileAttributesSerializer())
        result = self._rpc_client.call(GetAttrProc, handle.opaque, OpaqueVarLengthSerializer(), attr_deserializer)
        if isinstance(result, NfsStat):
            raise NfsError("Failed to get attributes", result)

        return result

    def readlink(self, handle: FileHandle) -> str:
        """Read the target of a symlink by its file handle."""
        link_deserializer = NfsResultDeserializer(ReadLink3ResultDeserializer())
        result = self._rpc_client.call(ReadLinkProc, handle.opaque, OpaqueVarLengthSerializer(), link_deserializer)
        if isinstance(result, NfsStat):
            raise NfsError("Failed to read link", result)

        return result.target

    def close(self) -> None:
        self._rpc_client.close()

    def __del__(self):
        self.close()
