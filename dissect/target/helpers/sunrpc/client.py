from __future__ import annotations

import random
import socket
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Generic, TypeVar

from dissect.target.helpers.sunrpc import sunrpc
from dissect.target.helpers.sunrpc.serializer import (
    AuthNullSerializer,
    AuthSerializer,
    AuthUnixSerializer,
    MessageSerializer,
    XdrDeserializer,
    XdrSerializer,
)

if TYPE_CHECKING:
    from types import TracebackType

    from dissect.target.helpers.nfs.nfs3 import ProcedureDescriptor


Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")
Params = TypeVar("Params")
Results = TypeVar("Results")


@dataclass
class AuthScheme(Generic[Credentials, Verifier]):
    credentials: Credentials
    verifier: Verifier
    credentials_serializer: AuthSerializer[Credentials]
    verifier_serializer: AuthSerializer[Verifier]


def auth_null() -> AuthScheme[sunrpc.AuthNull, sunrpc.AuthNull]:
    return AuthScheme(sunrpc.AuthNull(), sunrpc.AuthNull(), AuthNullSerializer(), AuthNullSerializer())


def auth_unix(machine: str | None, uid: int, gid: int, gids: list[int]) -> AuthScheme[sunrpc.AuthUnix, sunrpc.AuthNull]:
    stamp = random.randint(0, 2**32 - 1)

    if machine is None:
        machine = "dissect"

    return AuthScheme(
        sunrpc.AuthUnix(stamp, machine, uid, gid, gids),
        sunrpc.AuthNull(),
        AuthUnixSerializer(),
        AuthNullSerializer(),
    )


# RdJ: Error handing is a bit minimalistic. Expand later on.
class MismatchXidError(Exception):
    pass


class UnexpectedResponse(Exception):
    pass


class IncompleteMessage(Exception):
    pass


class Client(AbstractContextManager, Generic[Credentials, Verifier]):
    PMAP_PORT = 111

    @classmethod
    def connect_port_mapper(cls, hostname: str) -> Client:
        return cls.connect(hostname, cls.PMAP_PORT, auth_null())

    @classmethod
    def connect(cls, hostname: str, port: int, auth: AuthScheme[Credentials, Verifier], local_port: int = 0) -> Client:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", local_port))
        sock.connect((hostname, port))

        return Client(sock, auth)

    def __init__(self, sock: socket.socket, auth: AuthScheme[Credentials, Verifier], fragment_size: int = 8192):
        self._sock = sock
        self._auth = auth
        self._fragment_size = fragment_size
        self._xid = 1

    def __exit__(self, _: type[BaseException] | None, __: BaseException | None, ___: TracebackType | None) -> bool:
        self.close()
        return False  # Reraise exceptions

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # Ignore errors if the socket is already closed
        self._sock.close()

    def call(
        self,
        proc_desc: ProcedureDescriptor,
        params: Params,
        params_serializer: XdrSerializer[Params],
        result_deserializer: XdrDeserializer[Results],
    ) -> Results:
        """Synchronously call an RPC procedure and return the result"""

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
