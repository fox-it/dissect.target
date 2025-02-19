from __future__ import annotations

from contextlib import AbstractContextManager
from typing import TYPE_CHECKING

from dissect.target.exceptions import Error
from dissect.target.helpers.nfs.nfs3 import MountOK, MountProc, MountStat
from dissect.target.helpers.nfs.serializer import MountResultDeserializer
from dissect.target.helpers.sunrpc.client import AbstractClient as SunRpcAbstractClient
from dissect.target.helpers.sunrpc.client import Client as SunRpcClient
from dissect.target.helpers.sunrpc.client import FreePrivilegedPortType, auth_null
from dissect.target.helpers.sunrpc.serializer import StringSerializer

if TYPE_CHECKING:
    from types import TracebackType


class MountError(Error):
    def __init__(self, message: str, mount_stat: MountStat):
        super().__init__(message)
        self.message = message
        self.mount_stat = mount_stat

    def __str__(self) -> str:
        return f"{self.__class__.__name__} (Mount stat: {self.mount_stat}): {self.message}"


class Client(AbstractContextManager):
    DIR_COUNT = 4096  # See https://datatracker.ietf.org/doc/html/rfc1813#section-3.3.17
    MAX_COUNT = 32768
    READ_CHUNK_SIZE = 1024 * 1024

    def __init__(self, rpc_client: SunRpcAbstractClient):
        self._rpc_client = rpc_client

    def __enter__(self) -> Client:
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
        local_port: int | FreePrivilegedPortType = 0,
        timeout_in_seconds: float | None = 5.0,
    ) -> Client:
        rpc_client = SunRpcClient.connect(hostname, port, auth_null(), local_port, timeout_in_seconds)
        return Client(rpc_client)

    def close(self) -> None:
        self._rpc_client.close()

    def mount(self, remote_path: str) -> MountOK:
        result = self._rpc_client.call(MountProc, remote_path, StringSerializer(), MountResultDeserializer())
        if isinstance(result, MountStat):
            raise MountError("Failed to mount nfs share", result)

        return result
