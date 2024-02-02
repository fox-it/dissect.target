from io import BytesIO

import pytest
from dissect.cstruct import cstruct

from dissect.target.helpers.protobuf import ProtobufVarint, decode_varint, encode_varint


@pytest.mark.parametrize(
    "input, expected_output",
    [
        (b"\xd2\x85\xd8\xcc\x04", 1234567890),
        (b"\xd2\x85\xd8\xcc\x04\x01\x02\x03", 1234567890),
    ],
)
def test_protobuf_varint_decode(input: bytes, expected_output: int):
    assert decode_varint(BytesIO(input)) == expected_output


@pytest.mark.parametrize(
    "input, expected_output",
    [
        (1234567890, b"\xd2\x85\xd8\xcc\x04"),
        (pow(2, 128), b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x04"),
    ],
)
def test_protobuf_varint_encode(input: int, expected_output: bytes):
    assert encode_varint(input) == expected_output


def test_protobuf_varint_cstruct():
    struct_def = """
    struct foo {
        uint32 foo;
        varint size;
        char   bar[size];
    };
    """
    cs = cstruct(endian=">")
    cs.addtype("varint", ProtobufVarint(cstruct=cs, name="varint", size=1, signed=False, alignment=1))
    cs.load(struct_def, compiled=False)

    aaa = b"a" * 123456
    foo = cs.foo(BytesIO(b"\x00\x00\x00\x01\xc0\xc4\x07" + aaa + b"\x01\x02\x03"))
    assert foo.foo == 1
    assert foo.size == 123456
    assert foo.bar == aaa
