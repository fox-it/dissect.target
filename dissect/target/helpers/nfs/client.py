from typing import Generic, NamedTuple, TypeVar

from dissect.target.helpers.nfs.nfs import (
    CookieVerf3,
    EntryPlus3,
    FileAttributes3,
    FileHandle3,
    NfsStat,
    ReadDirPlusParams,
)
from dissect.target.helpers.nfs.serializer import (
    ReadDirPlusParamsSerializer,
    ReadDirPlusResultDeserializer,
)
from dissect.target.helpers.sunrpc.client import AuthScheme
from dissect.target.helpers.sunrpc.client import Client as SunRpcClient

Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")


class ReadDirResult(NamedTuple):
    dir_attributes: FileAttributes3 | None
    entries: list[EntryPlus3]


# RdJ Bit annoying that the Credentials and Verifier keep propagating as type parameters of the class.
# Alternatively, we could use type erasure and couple the auth data with the auth serializer,
# and make the auth data in the `CallBody` class opaque.
class Client(Generic[Credentials, Verifier]):
    DIR_COUNT = 4096  # See https://datatracker.ietf.org/doc/html/rfc1813#section-3.3.17
    MAX_COUNT = 32768

    def __init__(self, rpc_client: SunRpcClient[Credentials, Verifier]):
        self._rpc_client = rpc_client

    @classmethod
    def connect(cls, hostname: str, port: int, auth: AuthScheme[Credentials, Verifier], local_port: int) -> "Client":
        rpc_client = SunRpcClient.connect(hostname, port, auth, local_port)
        return Client(rpc_client)

    def readdirplus(self, dir: FileHandle3) -> list[EntryPlus3] | NfsStat:
        """Read the contents of a directory, including file attributes"""

        entries = list[EntryPlus3]()
        cookie = 0
        cookieverf = CookieVerf3(b"\x00")

        # Multiple calls might be needed to read the entire directory
        while True:
            params = ReadDirPlusParams(dir, cookie, cookieverf, dir_count=self.DIR_COUNT, max_count=self.MAX_COUNT)
            result = self._rpc_client.call(
                100003, 3, 17, params, ReadDirPlusParamsSerializer(), ReadDirPlusResultDeserializer()
            )
            if isinstance(result, NfsStat):
                return result

            entries += result.entries
            if result.eof or len(result.entries) == 0:
                return ReadDirResult(result.dir_attributes, entries)

            cookie = result.entries[-1].cookie
            cookieverf = result.cookieverf
