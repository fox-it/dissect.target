from __future__ import annotations


from abc import ABC, abstractmethod
from enum import Enum
import io
from typing import Generic, TypeVar
import sunrpc


ProcedureParams = TypeVar("ProcedureParams")
ProcedureResults = TypeVar("ProcedureResults")
Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")
Serializable = TypeVar("Serializable")
AuthProtocol = TypeVar("AuthProtocol")


class Serializer(ABC, Generic[Serializable]):
    ALIGNMENT = 4

    @abstractmethod
    def serialize(self, _: Serializable) -> bytes:
        pass

    @abstractmethod
    def deserialize(self, _: io.BytesIO) -> None:
        pass

    def _write_int(self, i: int) -> bytes:
        return i.to_bytes(length=4, byteOrder="big", signed=False)

    def _write_var_length_opaque(self, body: bytes) -> bytes:
        length = len(body)
        result = self.write_int(length)
        result += body

        padding_bytes = (length + self.ALIGNMENT - 1) / self.ALIGNMENT
        return result + b"\x00" * padding_bytes


class AuthFlavor(Enum):
    AUTH_NULL = 0
    AUTH_UNIX = 1
    AUTH_SHORT = 2
    AUTH_DES = 3


class AuthSerializer(Generic[AuthProtocol], Serializer[AuthProtocol]):
    def serialize(self, protocol: AuthProtocol) -> bytes:
        flavor = self._flavor()
        result = self._write_int(flavor)

        body = self._write_body(protocol)
        return result + self._write_var_length_opaque(body)

    def deserialize(self, _: io.BytesIO) -> AuthProtocol:
        pass

    @abstractmethod
    def _flavor() -> int:
        pass

    @abstractmethod
    def _write_body(self, _: AuthProtocol) -> bytes:
        pass

    @abstractmethod
    def _read_body(self, _: bytes) -> AuthProtocol:
        pass


class AuthNullSerializer(AuthSerializer[sunrpc.AuthNull]):
    def _flavor() -> int:
        return AuthFlavor.AUTH_NULL

    def _write_body(self, _: AuthProtocol) -> bytes:
        return bytes()

    def _read_body(self, _: bytes) -> AuthProtocol:
        return sunrpc.AuthNull()


class MessageSerializer(
    Generic[ProcedureParams, ProcedureResults, Credentials, Verifier],
    Serializer[sunrpc.Message[ProcedureParams, ProcedureResults, Credentials, Verifier]],
):
    def __init__(
        self,
        paramsSerializer: Serializer[ProcedureParams],
        credentialsSerializer: Serializer[Credentials],
        verifierSerializer: Serializer[Verifier],
    ):
        self._paramsSerializer = paramsSerializer
        self._credentialsSerializer = credentialsSerializer
        self._verifierSerializer = verifierSerializer

    def serialize(self, message: sunrpc.Message[ProcedureParams, ProcedureResults, Credentials, Verifier]) -> bytes:
        result = self._write_int(message.xid)
        result += self._write_int(message.type.value)

        if message.type == sunrpc.MessageType.CALL:
            return result + self._paramsSerializer.serialize(message.body)

        raise NotImplementedError("Only call messages are supported")

    def _write_call_body(self, call_body: sunrpc.CallBody) -> bytes:
        result = self._write_int(call_body.rpc_version)
        result += self._write_int(call_body.program)
        result += self._write_int(call_body.version)
        result += self._write_int(call_body.procedure)
        result += self._credentialsSerializer.serialize(call_body.cred)
        result += self._verifierSerializer.serialize(call_body.verf)
        result += self._paramsSerializer.serialize(call_body.params)
        return result
