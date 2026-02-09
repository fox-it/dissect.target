from __future__ import annotations

from io import BytesIO

import pytest
from dissect.cstruct import cstruct

from dissect.target.helpers.protobuf import ProtobufVarint, decode_varint, encode_varint


@pytest.mark.parametrize(
    ("input", "expected_output"),
    [
        (b"\xd2\x85\xd8\xcc\x04", 1234567890),
        (b"\xd2\x85\xd8\xcc\x04\x01\x02\x03", 1234567890),
    ],
)
def test_protobuf_varint_decode(input: bytes, expected_output: int) -> None:
    assert decode_varint(BytesIO(input)) == expected_output


@pytest.mark.parametrize(
    ("input", "expected_output"),
    [
        (1234567890, b"\xd2\x85\xd8\xcc\x04"),
        (pow(2, 128), b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x04"),
    ],
)
def test_protobuf_varint_encode(input: int, expected_output: bytes) -> None:
    assert encode_varint(input) == expected_output


def test_protobuf_varint_cstruct() -> None:
    struct_def = """
    struct foo {
        uint32 foo;
        varint size;
        char   bar[size];
    };
    """
    cs = cstruct(endian=">")
    cs.add_custom_type("varint", ProtobufVarint, size=None, alignment=1, signed=False)
    cs.load(struct_def, compiled=False)

    aaa = b"a" * 123456
    buf = b"\x00\x00\x00\x01\xc0\xc4\x07" + aaa
    foo = cs.foo(buf + b"\x01\x02\x03")
    assert foo.foo == 1
    assert foo.size == 123456
    assert foo.bar == aaa
    assert foo.dumps() == buf

    assert cs.varint[2](b"\x80\x01\x80\x02") == [128, 256]
    assert cs.varint[2].dumps([128, 256]) == b"\x80\x01\x80\x02"
