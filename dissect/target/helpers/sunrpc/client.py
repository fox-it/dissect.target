from __future__ import annotations

import random
import socket
import sys
from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Generic, TypeVar

from dissect.target.helpers.sunrpc import sunrpc
from dissect.target.helpers.sunrpc.serializer import (
    AuthFlavor,
    AuthNullSerializer,
    AuthSerializer,
    AuthUnixSerializer,
    Deserializer,
    MessageSerializer,
    PortMappingSerializer,
    Serializer,
    UInt32Serializer,
)

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self

    from dissect.target.helpers.nfs.nfs3 import ProcedureDescriptor


Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")
ConCredentials = TypeVar("ConCredentials")
ConVerifier = TypeVar("ConVerifier")
Params = TypeVar("Params")
Results = TypeVar("Results")


@dataclass
class AuthScheme(Generic[Credentials, Verifier]):
    flavor: int
    credentials: Credentials
    verifier: Verifier
    credentials_serializer: AuthSerializer[Credentials]
    verifier_serializer: AuthSerializer[Verifier]


def auth_null() -> AuthScheme[sunrpc.AuthNull, sunrpc.AuthNull]:
    return AuthScheme(
        AuthFlavor.AUTH_NULL.value, sunrpc.AuthNull(), sunrpc.AuthNull(), AuthNullSerializer(), AuthNullSerializer()
    )


def auth_unix(machine: str | None, uid: int, gid: int, gids: list[int]) -> AuthScheme[sunrpc.AuthUnix, sunrpc.AuthNull]:
    stamp = random.randint(0, 2**32 - 1)

    if machine is None:
        machine = "dissect"

    return AuthScheme(
        AuthFlavor.AUTH_UNIX.value,
        sunrpc.AuthUnix(stamp, machine, uid, gid, gids),
        sunrpc.AuthNull(),
        AuthUnixSerializer(),
        AuthNullSerializer(),
    )


class MismatchXidError(Exception):
    pass


class UnexpectedResponse(Exception):
    pass


class IncompleteMessage(Exception):
    pass


class InvalidPortMapping(Exception):
    pass


class AbstractClient(ABC):
    @abstractmethod
    def call(
        self,
        proc_desc: ProcedureDescriptor,
        params: Params,
        params_serializer: Serializer[Params],
        result_deserializer: Deserializer[Results],
    ) -> Results:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def rebind_auth(self, auth: AuthScheme[ConCredentials, ConVerifier]) -> None:
        pass


class LocalPortPolicy(IntEnum):
    """Policy for binding to a local port."""

    ANY = 0  # Bind to any free port
    PRIVILEGED = -1  # Bind to the first free privileged port


class Client(AbstractContextManager, AbstractClient, Generic[Credentials, Verifier]):
    PMAP_PORT = 111
    TCP_KEEPIDLE = 60
    TCP_KEEPINTVL = 10
    TCP_KEEPCNT = 3

    @classmethod
    def connect_port_mapper(
        cls, hostname: str, timeout_in_seconds: float | None = 5.0
    ) -> Client[sunrpc.AuthNull, sunrpc.AuthNull]:
        """Connect to the port mapper service on a remote host."""
        return cls.connect(
            hostname,
            cls.PMAP_PORT,
            auth_null(),
            local_port=0,
            timeout_in_seconds=timeout_in_seconds,
        )

    @classmethod
    def connect(
        cls,
        hostname: str,
        port: int,
        auth: AuthScheme[ConCredentials, ConVerifier],
        local_port: int | LocalPortPolicy = 0,
        timeout_in_seconds: float | None = 5.0,
    ) -> Client[ConCredentials, ConVerifier]:
        """Connect to a RPC server.

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

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if not sys.platform.startswith("darwin"):
            # MacOS does not support TCP_KEEPIDLE, and TCP_KEEPALIVE is only available in Python 3.10
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, cls.TCP_KEEPIDLE)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, cls.TCP_KEEPINTVL)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, cls.TCP_KEEPCNT)

        local_port_int = local_port.value if isinstance(local_port, LocalPortPolicy) else local_port
        if local_port_int == LocalPortPolicy.PRIVILEGED:
            cls._bind_free_privileged_port(sock)
        else:
            sock.bind(("", local_port_int))

        sock.settimeout(timeout_in_seconds)
        sock.connect((hostname, port))
        sock.settimeout(None)  # Back to blocking mode

        return Client(sock, auth)

    @classmethod
    def _bind_free_privileged_port(cls, sock: socket.socket) -> None:
        """Bind to a free privileged port (1-1023)."""
        for port in range(1, 1024):
            try:
                return sock.bind(("", port))
            except OSError:  # noqa: PERF203
                continue

        raise OSError("No free privileged port available")

    def __init__(self, sock: socket.socket, auth: AuthScheme[Credentials, Verifier], fragment_size: int = 8192):
        self._sock = sock
        self._auth = auth
        self._fragment_size = fragment_size
        self._xid = 1

    def __enter__(self) -> Self:
        """Return ``self`` upon entering the runtime context."""
        return self  # type: Necessary for type checker

    def __exit__(self, _: type[BaseException] | None, __: BaseException | None, ___: TracebackType | None) -> bool:
        self.close()
        return False  # Reraise exceptions

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # Ignore errors if the socket is already closed
        self._sock.close()

    def rebind_auth(self, auth: AuthScheme[ConCredentials, ConVerifier]) -> Client[ConCredentials, ConVerifier]:
        """Return a new client with the same socket, but different authentication credentials."""
        fd = self._sock.detach()  # Move underlying file descriptor to new socket
        new_sock = socket.socket(fileno=fd)
        return Client(new_sock, auth, self._fragment_size)

    def query_port_mapping(self, program: int, version: int) -> int:
        """Query port number of specified program and version."""
        arg = sunrpc.PortMapping(program=program, version=version, protocol=sunrpc.Protocol.TCP)
        result = self.call(sunrpc.GetPortProc, arg, PortMappingSerializer(), UInt32Serializer())
        if result == 0:
            raise InvalidPortMapping("Invalid port mapping")
        return result

    def call(
        self,
        proc_desc: ProcedureDescriptor,
        params: Params,
        params_serializer: Serializer[Params],
        result_deserializer: Deserializer[Results],
    ) -> Results:
        """Synchronously call an RPC procedure and return the result."""

        call_body = sunrpc.CallBody(
            proc_desc.program,
            proc_desc.version,
            proc_desc.procedure,
            self._auth.credentials,
            self._auth.verifier,
            params,
        )
        message = sunrpc.Message(self._xid, call_body)
        message_serializer = MessageSerializer(
            params_serializer, result_deserializer, self._auth.credentials_serializer, self._auth.verifier_serializer
        )
        request_payload = message_serializer.serialize(message)
        self._send(request_payload)

        response_payload = self._receive()
        response = message_serializer.deserialize_from_bytes(response_payload)
        if response.xid != self._xid:
            raise MismatchXidError("Invalid response xid")
        if not isinstance(response.body, sunrpc.AcceptedReply):
            raise UnexpectedResponse("Unexpected response type")
        if response.body.stat != sunrpc.AcceptStat.SUCCESS:
            raise UnexpectedResponse("Call failed")

        self._xid += 1
        return response.body.results

    def _send(self, data: bytes) -> None:
        data_size = len(data)
        offset = 0

        # Messages are split into fragments: 4 bytes for the fragment size, followed by the fragment data
        while offset < data_size:
            fragment = data[offset : offset + self._fragment_size]
            fragment_size = len(fragment)

            fragment_header = fragment_size
            if offset + fragment_size == data_size:
                fragment_header = fragment_header | 0x80000000  # MSB set to indicate last fragment

            chunk = fragment_header.to_bytes(4, "big") + fragment
            self._sock.sendall(chunk)
            offset += fragment_size

    def _receive(self) -> bytes:
        fragments = []

        while True:
            header = self._sock.recv(4)
            if not header:
                raise IncompleteMessage("Expected a fragment header")

            fragment_header = int.from_bytes(header, "big")
            fragment_size = fragment_header & 0x7FFFFFFF
            while fragment_size > 0:
                fragment = self._sock.recv(fragment_size)
                fragments.append(fragment)
                fragment_size -= len(fragment)

            # Check for last fragment
            if fragment_header & 0x80000000:
                return b"".join(fragments)

    def __del__(self):
        self._sock.close()
