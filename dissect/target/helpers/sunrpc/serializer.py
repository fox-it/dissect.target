from __future__ import annotations

import io
from abc import ABC, abstractmethod
from enum import IntEnum
from typing import Generic, TypeVar

from dissect.target.helpers.sunrpc import sunrpc

ProcedureParams = TypeVar("ProcedureParams")
ProcedureResults = TypeVar("ProcedureResults")
Credentials = TypeVar("Credentials")
Verifier = TypeVar("Verifier")
Serializable = TypeVar("Serializable")
AuthProtocol = TypeVar("AuthProtocol")
EnumType = TypeVar("EnumType", bound=IntEnum)
ElementType = TypeVar("ElementType")


class MessageType(IntEnum):
    CALL = 0
    REPLY = 1


ALIGNMENT = 4


class Serializer(ABC, Generic[Serializable]):
    @abstractmethod
    def serialize(self, _: Serializable) -> bytes:
        pass


class Deserializer(ABC, Generic[Serializable]):
    def deserialize_from_bytes(self, payload: bytes) -> Serializable:
        return self.deserialize(io.BytesIO(payload))

    @abstractmethod
    def deserialize(self, _: io.BytesIO) -> Serializable:
        pass


# Unfortunately xdrlib is deprecated in Python 3.11, so we implement the following serialization classes
# See https://datatracker.ietf.org/doc/html/rfc1014 for the XDR specification.


class Int32Serializer(Serializer[int], Deserializer[int]):
    _signed = True

    def serialize(self, i: int) -> bytes:
        return i.to_bytes(length=4, byteorder="big", signed=self._signed)

    def deserialize(self, payload: io.BytesIO) -> int:
        return int.from_bytes(payload.read(4), byteorder="big", signed=self._signed)


class UInt32Serializer(Int32Serializer):
    _signed = False


class OpaqueVarLengthSerializer(Serializer[bytes], Deserializer[bytes]):
    def serialize(self, body: bytes) -> bytes:
        length = len(body)
        result = UInt32Serializer().serialize(length)
        result += body

        padding_bytes = (ALIGNMENT - (length % ALIGNMENT)) % ALIGNMENT
        return result + b"\x00" * padding_bytes

    def deserialize(self, payload: io.BytesIO) -> bytes:
        length = UInt32Serializer().deserialize(payload)
        result = payload.read(length)
        padding_bytes = (ALIGNMENT - (length % ALIGNMENT)) % ALIGNMENT
        payload.read(padding_bytes)
        return result


class StringSerializer(Serializer[str], Deserializer[str]):
    def serialize(self, s: str) -> bytes:
        return OpaqueVarLengthSerializer().serialize(s.encode("ascii"))

    def deserialize(self, payload: io.BytesIO) -> str:
        return OpaqueVarLengthSerializer().deserialize(payload).decode("ascii")


class XdrSerializer(Generic[Serializable], Serializer[Serializable]):
    def _write_uint32(self, i: int) -> bytes:
        return UInt32Serializer().serialize(i)

    def _write_int32(self, i: int) -> bytes:
        return Int32Serializer().serialize(i)

    def _write_uint64(self, i: int) -> bytes:
        return i.to_bytes(length=8, byteorder="big", signed=False)

    def _write_enum(self, enum: EnumType) -> bytes:
        return self._write_int32(enum.value)

    def _write_var_length(self, elements: list[ElementType], serializer: Serializer[ElementType]) -> bytes:
        result = self._write_uint32(len(elements))
        payload = (serializer.serialize(element) for element in elements)
        return result + b"".join(payload)

    def _write_var_length_opaque(self, body: bytes) -> bytes:
        return OpaqueVarLengthSerializer().serialize(body)

    def _write_string(self, s: str) -> bytes:
        return StringSerializer().serialize(s)


class XdrDeserializer(Generic[Serializable], Deserializer[Serializable]):
    def _read_uint32(self, payload: io.BytesIO) -> int:
        return UInt32Serializer().deserialize(payload)

    def _read_int32(self, payload: io.BytesIO) -> int:
        return Int32Serializer().deserialize(payload)

    def _read_uint64(self, payload: io.BytesIO) -> int:
        return int.from_bytes(payload.read(8), byteorder="big", signed=False)

    def _read_enum(self, payload: io.BytesIO, enum: type[EnumType]) -> EnumType:
        value = self._read_int32(payload)
        return enum(value)

    def _read_var_length(self, payload: io.BytesIO, deserializer: Deserializer[ElementType]) -> list[ElementType]:
        length = self._read_uint32(payload)
        return [deserializer.deserialize(payload) for _ in range(length)]

    def _read_var_length_opaque(self, payload: io.BytesIO) -> bytes:
        return OpaqueVarLengthSerializer().deserialize(payload)

    def _read_string(self, payload: io.BytesIO) -> str:
        return StringSerializer().deserialize(payload)

    def _read_optional(self, payload: io.BytesIO, deserializer: Deserializer[ElementType]) -> ElementType | None:
        has_value = self._read_enum(payload, sunrpc.Bool)
        if has_value == sunrpc.Bool.FALSE:
            return None
        return deserializer.deserialize(payload)


class ReplyStat(IntEnum):
    MSG_ACCEPTED = 0
    MSG_DENIED = 1


class AuthFlavor(IntEnum):
    AUTH_NULL = 0
    AUTH_UNIX = 1
    AUTH_SHORT = 2
    AUTH_DES = 3


class AuthSerializer(Generic[AuthProtocol], XdrSerializer[AuthProtocol], XdrDeserializer[AuthProtocol]):
    def serialize(self, protocol: AuthProtocol) -> bytes:
        flavor = self._flavor()
        result = self._write_int32(flavor)

        body = self._write_body(protocol)
        return result + self._write_var_length_opaque(body)

    def deserialize(self, payload: io.BytesIO) -> AuthProtocol:
        flavor = self._read_int32(payload)
        if flavor != self._flavor():
            raise ValueError(f"Expected flavor {self._flavor()}, got {flavor}")

        body = self._read_var_length_opaque(payload)
        return self._read_body(io.BytesIO(body))

    # The return type is not AuthFlavor, because AuthProtocol is open to extension.
    @abstractmethod
    def _flavor(self) -> int:
        pass

    @abstractmethod
    def _write_body(self, _: AuthProtocol) -> bytes:
        pass

    @abstractmethod
    def _read_body(self, _: io.BytesIO) -> AuthProtocol:
        pass


class AuthNullSerializer(AuthSerializer[sunrpc.AuthNull]):
    def _flavor(self) -> int:
        return AuthFlavor.AUTH_NULL.value

    def _write_body(self, _: AuthProtocol) -> bytes:
        return b""

    def _read_body(self, _: io.BytesIO) -> AuthProtocol:
        return sunrpc.AuthNull()


class AuthUnixSerializer(AuthSerializer[sunrpc.AuthUnix]):
    def _flavor(self) -> int:
        return AuthFlavor.AUTH_UNIX.value

    def _write_body(self, protocol: sunrpc.AuthUnix) -> bytes:
        result = self._write_uint32(protocol.stamp)
        result += self._write_string(protocol.machinename)
        result += self._write_uint32(protocol.uid)
        result += self._write_uint32(protocol.gid)
        result += self._write_var_length(protocol.gids, Int32Serializer())
        return result

    def _read_body(self, payload: io.BytesIO) -> sunrpc.AuthUnix:
        stamp = self._read_uint32(payload)
        machinename = self._read_string(payload)
        uid = self._read_uint32(payload)
        gid = self._read_uint32(payload)
        gids = self._read_var_length(payload, Int32Serializer())
        return sunrpc.AuthUnix(stamp, machinename, uid, gid, gids)


class MessageSerializer(
    Generic[ProcedureParams, ProcedureResults, Credentials, Verifier],
    XdrSerializer[sunrpc.Message[ProcedureParams, ProcedureResults, Credentials, Verifier]],
    XdrDeserializer[sunrpc.Message[ProcedureParams, ProcedureResults, Credentials, Verifier]],
):
    def __init__(
        self,
        params_serializer: XdrSerializer[ProcedureParams],
        results_deserializer: XdrDeserializer[ProcedureResults],
        credentials_serializer: AuthSerializer[Credentials],
        verifier_serializer: AuthSerializer[Verifier],
    ):
        self._params_serializer = params_serializer
        self._results_deserializer = results_deserializer
        self._credentials_serializer = credentials_serializer
        self._verifier_serializer = verifier_serializer

    def serialize(self, message: sunrpc.Message[ProcedureParams, ProcedureResults, Credentials, Verifier]) -> bytes:
        if not isinstance(message.body, sunrpc.CallBody):
            raise NotImplementedError("Only CALL messages are serializable")

        result = self._write_uint32(message.xid)
        result += self._write_enum(MessageType.CALL)
        return result + self._write_call_body(message.body)

    def deserialize(
        self, payload: io.BytesIO
    ) -> sunrpc.Message[ProcedureParams, ProcedureResults, Credentials, Verifier]:
        xid = self._read_uint32(payload)
        message_type = self._read_enum(payload, MessageType)
        if message_type != MessageType.REPLY:
            raise NotImplementedError("Only REPLY messages are deserializable")

        reply_stat = self._read_enum(payload, ReplyStat)
        if reply_stat == ReplyStat.MSG_ACCEPTED:
            reply = self._read_accepted_reply(payload)
        elif reply_stat == ReplyStat.MSG_DENIED:
            reply = self._read_rejected_reply(payload)
        else:
            # assert_never is slightly better, but only available starting from Python 3.11
            raise ValueError(f"Unexpected value for reply_stat {reply_stat}")

        return sunrpc.Message(xid, reply)

    def _write_call_body(self, call_body: sunrpc.CallBody) -> bytes:
        result = self._write_uint32(call_body.rpc_version)
        result += self._write_uint32(call_body.program)
        result += self._write_uint32(call_body.version)
        result += self._write_uint32(call_body.procedure)
        result += self._credentials_serializer.serialize(call_body.cred)
        result += self._verifier_serializer.serialize(call_body.verf)
        result += self._params_serializer.serialize(call_body.params)
        return result

    def _read_accepted_reply(self, payload: io.BytesIO) -> sunrpc.AcceptedReply[ProcedureResults, Verifier]:
        verf = self._verifier_serializer.deserialize(payload)
        stat = self._read_enum(payload, sunrpc.AcceptStat)
        if stat == sunrpc.AcceptStat.SUCCESS:
            results = self._results_deserializer.deserialize(payload)
        elif stat == sunrpc.AcceptStat.PROG_MISMATCH:
            results = self._read_mismatch(payload)
        else:
            # Void in case of PROG_UNAVAIL, PROC_UNAVAIL, GARBAGE_ARGS
            results = None

        return sunrpc.AcceptedReply(verf, stat, results)

    def _read_rejected_reply(self, payload: io.BytesIO) -> sunrpc.RejectedReply:
        reject_stat = self._read_enum(payload, sunrpc.RejectStat)
        if reject_stat == sunrpc.RejectStat.RPC_MISMATCH:
            mismatch = self._read_mismatch(payload)
            return sunrpc.RejectedReply(reject_stat, mismatch)
        if reject_stat == sunrpc.RejectStat.AUTH_ERROR:
            auth_stat = self._read_enum(payload, sunrpc.AuthStat)
            return sunrpc.RejectedReply(reject_stat, auth_stat)

        # assert_never is slightly better, but only available starting from Python 3.11
        raise ValueError(f"Unexpected value for reject_stat: {reject_stat}")

    def _read_mismatch(self, payload: io.BytesIO) -> sunrpc.Mismatch:
        low = self._read_uint32(payload)
        high = self._read_uint32(payload)
        return sunrpc.Mismatch(low, high)


class PortMappingSerializer(XdrSerializer[sunrpc.PortMapping]):
    def serialize(self, port_mapping: sunrpc.PortMapping) -> bytes:
        result = self._write_uint32(port_mapping.program)
        result += self._write_uint32(port_mapping.version)
        result += self._write_enum(port_mapping.protocol)
        result += self._write_uint32(port_mapping.port)
        return result
