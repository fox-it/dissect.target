from __future__ import annotations

from typing import Any, BinaryIO

from dissect.cstruct.types.base import BaseType


class ProtobufVarint(BaseType):
    """Implements a protobuf integer type for dissect.cstruct that can span a variable amount of bytes.

    Supports protobuf's msb varint implementation.

    Resources:
        - https://protobuf.dev/programming-guides/encoding/
        - https://github.com/protocolbuffers/protobuf/blob/main/python/google/protobuf/internal/decoder.py
    """

    @classmethod
    def _read(cls, stream: BinaryIO, context: dict[str, Any] | None = None) -> int:
        return decode_varint(stream)

    @classmethod
    def _write(cls, stream: BinaryIO, data: int) -> int:
        return stream.write(encode_varint(data))


def decode_varint(stream: BinaryIO) -> int:
    """Reads a varint from the provided buffer stream.

    If we have not reached the end of a varint, the msb will be 1.
    We read every byte from our current position until the msb is 0.
    """
    result = 0
    i = 0
    while True:
        byte = stream.read(1)
        result |= (byte[0] & 0x7F) << (i * 7)
        i += 1
        if byte[0] & 0x80 == 0:
            break

    return result


def encode_varint(number: int) -> bytes:
    """Encode a decoded protobuf varint to its original bytes."""
    buf = []
    while True:
        towrite = number & 0x7F
        number >>= 7
        if number:
            buf.append(towrite | 0x80)
        else:
            buf.append(towrite)
            break
    return bytes(buf)
