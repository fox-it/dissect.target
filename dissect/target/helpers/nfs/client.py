from __future__ import annotations

from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Generic, Iterator, NamedTuple, TypeVar

from dissect.target.helpers.nfs.nfs3 import (
    CookieVerf3,
    EntryPlus3,
    FileAttributes3,
    FileHandle3,
    Nfs3Stat,
    Read3args,
    ReadDirPlusParams,
    ReadDirPlusProc,
    ReadFileProc,
)
from dissect.target.helpers.nfs.serializer import (
    Read3ArgsSerializer,
    Read3ResultDeserializer,
    ReadDirPlusParamsSerializer,
    ReadDirPlusResultDeserializer,
)
from dissect.target.helpers.sunrpc.client import AuthScheme
from dissect.target.helpers.sunrpc.client import Client as SunRpcClient

if TYPE_CHECKING:
    from types import TracebackType

Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")


class ReadFileError(Exception):
    pass


class ReadDirResult(NamedTuple):
    dir_attributes: FileAttributes3 | None
    entries: list[EntryPlus3]


# RdJ Bit annoying that the Credentials and Verifier keep propagating as type parameters of the class.
# Alternatively, we could use type erasure and couple the auth data with the auth serializer,
# and make the auth data in the `CallBody` class opaque.
class Client(AbstractContextManager, Generic[Credentials, Verifier]):
    DIR_COUNT = 4096  # See https://datatracker.ietf.org/doc/html/rfc1813#section-3.3.17
    MAX_COUNT = 32768
    READ_CHUNK_SIZE = 1024 * 1024

    def __init__(self, rpc_client: SunRpcClient[Credentials, Verifier]):
        self._rpc_client = rpc_client

    def __exit__(self, _: type[BaseException] | None, __: BaseException | None, ___: TracebackType | None) -> bool:
        self._rpc_client.close()
        return False  # Reraise exceptions

    @classmethod
    def connect(cls, hostname: str, port: int, auth: AuthScheme[Credentials, Verifier], local_port: int) -> Client:
        rpc_client = SunRpcClient.connect(hostname, port, auth, local_port)
        return Client(rpc_client)

    def readdirplus(self, dir: FileHandle3) -> ReadDirResult | Nfs3Stat:
        """Read the contents of a directory, including file attributes"""

        entries = list[EntryPlus3]()
        cookie = 0
        cookieverf = CookieVerf3(b"\x00")

        # Multiple calls might be needed to read the entire directory
        while True:
            params = ReadDirPlusParams(dir, cookie, cookieverf, dir_count=self.DIR_COUNT, max_count=self.MAX_COUNT)
            result = self._rpc_client.call(
                ReadDirPlusProc, params, ReadDirPlusParamsSerializer(), ReadDirPlusResultDeserializer()
            )
            if isinstance(result, Nfs3Stat):
                return result

            entries += result.entries
            if result.eof or len(result.entries) == 0:
                return ReadDirResult(result.dir_attributes, entries)

            cookie = result.entries[-1].cookie
            cookieverf = result.cookieverf

    def readfile_by_handle(self, handle: FileHandle3) -> Iterator[bytes]:
        """Read a file by its file handle"""
        offset = 0
        count = self.READ_CHUNK_SIZE
        while True:
            params = Read3args(handle, offset, count)
            result = self._rpc_client.call(ReadFileProc, params, Read3ArgsSerializer(), Read3ResultDeserializer())
            if isinstance(result, Nfs3Stat):
                raise ReadFileError(f"Failed to read file: {result}")
            yield result.data
            if result.eof:
                return
            offset += result.count
