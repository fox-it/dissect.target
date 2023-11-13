from __future__ import annotations

from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.cstruct.types.bytesinteger import BytesInteger

if TYPE_CHECKING:
    from dissect.cstruct import cstruct


class ProtobufVarint(BytesInteger):
    """Implements a protobuf integer type for dissect.cstruct that can span a variable amount of bytes.

    Mainly follows the cstruct BytesInteger implementation with minor tweaks
    to support protobuf's msb varint implementation.

    Resources:
        - https://protobuf.dev/programming-guides/encoding/
        - https://github.com/protocolbuffers/protobuf/blob/main/python/google/protobuf/internal/decoder.py
    """

    def __init__(self, cstruct: cstruct, name: str, size: int, signed: bool, alignment: int = None):
        self.signed = signed
        super().__init__(cstruct, name, size, alignment)

    def _read(self, stream: BinaryIO, context: dict[str, Any] = None) -> int:
        self.size, data = read_varint(stream)
        return decode_varint(data)

    def _write(self, stream: BinaryIO, data: int) -> int:
        return stream.write(encode_varint(data))


def read_varint(stream: BinaryIO) -> tuple[int, bytes]:
    """Reads a varint from the provided buffer stream.

    Returns the size and bytes of the found protobuf varint.

    If we have not reached the end of a varint, the msb will be 1.
    We read every byte from our current position until the msb is 0.
    """
    size = 0
    data = b""

    while True:
        size += 1
        byte = stream.read(1)
        data += byte
        if int.from_bytes(byte, byteorder="big") & 0x80 == 0:
            break

    return size, data


def decode_varint(data: bytes) -> int:
    """Decode a protobuf varint."""
    result = 0
    for i, byte in enumerate(data):
        result |= (byte & 0x7F) << (i * 7)
        if byte & 0x80 == 0:
            break
    return result


def encode_varint(number: int) -> bytes:
    """Encode a decoded protobuf varint to its original bytes."""
    buf = b""
    while True:
        towrite = number & 0x7F
        number >>= 7
        if number:
            buf += bytes((towrite | 0x80,))
        else:
            buf += bytes((towrite,))
            break
    return buf
