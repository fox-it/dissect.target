from __future__ import annotations

import random
import socket
from typing import Generic, NamedTuple, TypeVar

from dissect.target.helpers.sunrpc import sunrpc
from dissect.target.helpers.sunrpc.serializer import (
    AuthNullSerializer,
    AuthSerializer,
    AuthUnixSerializer,
    Deserializer,
    MessageSerializer,
    Serializer,
)

Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")
Params = TypeVar("Params")
Results = TypeVar("Results")


class AuthScheme(Generic[Credentials, Verifier], NamedTuple):
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


class Client(Generic[Credentials, Verifier]):
    PMAP_PORT = 111

    @classmethod
    def connectPortMapper(cls, hostname: str) -> "Client":
        return cls.connect(hostname, cls.PMAP_PORT, auth_null())

    @classmethod
    def connect(
        cls, hostname: str, port: int, auth: AuthScheme[Credentials, Verifier], local_port: int = 0
    ) -> "Client":
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

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # Ignore errors if the socket is already closed
        self._sock.close()

    def call(
        self,
        program: int,
        version: int,
        procedure: int,
        params: Params,
        params_serializer: Serializer[Params],
        result_deserializer: Deserializer[Results],
    ) -> Results:
        callBody = sunrpc.CallBody(program, version, procedure, self._auth.credentials, self._auth.verifier, params)
        message = sunrpc.Message(self._xid, callBody)
        messageSerializer = MessageSerializer(
            params_serializer, result_deserializer, self._auth.credentials_serializer, self._auth.verifier_serializer
        )
        requestPayload = messageSerializer.serialize(message)
        self._send(requestPayload)

        responsePayload = self._receive()
        response = messageSerializer.deserialize_from_bytes(responsePayload)
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

            if offset + fragment_size == data_size:
                fragmentHeader = fragment_size | 0x80000000  # MSB set to indicate last fragment
            else:
                fragmentHeader = fragment_size

            chunk = fragmentHeader.to_bytes(4, "big") + fragment
            self._sock.sendall(chunk)
            offset += fragment_size

    def _receive(self) -> bytes:
        fragments = []

        while True:
            header = self._sock.recv(4)
            if not header:
                return bytes()

            fragment_header = int.from_bytes(header, "big")
            fragment_size = fragment_header & 0x7FFFFFFF
            while fragment_size > 0:
                fragment = self._sock.recv(fragment_size)
                fragments.append(fragment)
                fragment_size -= len(fragment)

            # Check for last fragment or underflow
            if (fragment_header & 0x80000000) > 0 or len(fragment) < fragment_size:
                return b"".join(fragments)

    def __del__(self):
        self._sock.close()
