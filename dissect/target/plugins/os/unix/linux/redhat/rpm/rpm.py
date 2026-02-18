from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, Any

from dissect.cstruct.utils import u8, u16, u32, u64

from dissect.target.helpers.logging import get_logger
from dissect.target.plugins.os.unix.linux.redhat.rpm.c_rpm import c_rpm

if TYPE_CHECKING:
    from collections.abc import Callable

log = get_logger(__name__)


def parse_blob(blob: bytes) -> dict:
    """Parse a RPM package blob. Does not parse dribble entries (yet).

    References:
        - https://github.com/rpm-software-management/rpm/blob/master/lib/backend/ndb/rpmpkg.c
        - https://github.com/rpm-software-management/rpm/blob/master/lib/tagexts.cc @ getNEVRA
        - https://github.com/knqyf263/go-rpmdb
    """
    fh = BytesIO(blob)
    header = c_rpm.Header(fh)
    offset = fh.tell()
    package = {}

    for entry in header.pe_list:
        fh.seek(offset + entry.offset)

        type_size = c_rpm.TypeSizes[entry.type.name]

        # Read null terminated strings n-times for string-types.
        if entry.type in (c_rpm.TagType.STRING, c_rpm.TagType.STRING_ARRAY, c_rpm.TagType.I18NSTRING):
            data = b"".join([c_rpm.NullTerminatedStr(fh).dumps() for _ in range(entry.count)])

        else:
            # In theory entry.type.value can be above 16, so value & 0xf to keep value below 16?
            size = type_size * entry.count
            data = fh.read(size)

        if entry.tag.name:
            result = deserialize(entry.type, type_size, entry.count, data)

            if entry.count > 1 and len(result) != entry.count:
                raise ValueError(f"Deserialization of array failed, mismatch in count and array length: {entry!r}")

            package[entry.tag.name.lower()] = result

        else:
            # We should have all tags, log if we encounter a new one that should be added.
            log.warning("Encountered unknown RPM tag value %r in: %r", entry.tag.value, entry)

    return package


DESERIALIZE_MAP: dict[c_rpm.TagType, Callable] = {
    c_rpm.TagType.NULL: lambda _: None,
    c_rpm.TagType.CHAR: lambda b, _: b,
    c_rpm.TagType.INT8: lambda b, _: u8(b, "big"),
    c_rpm.TagType.INT16: lambda b, _: u16(b, "big"),
    c_rpm.TagType.INT32: lambda b, _: u32(b, "big"),
    c_rpm.TagType.INT64: lambda b, _: u64(b, "big"),
    c_rpm.TagType.STRING: lambda b, _: b.decode().strip("\x00"),
    c_rpm.TagType.BIN: lambda b, _: b,
    c_rpm.TagType.STRING_ARRAY: lambda b, c: [i.decode().strip("\x00") for i in b.split(b"\x00", maxsplit=c - 1)],
    c_rpm.TagType.I18NSTRING: lambda b, _: b.decode().strip("\x00"),
}


def deserialize(type: c_rpm.TagType, size: int, count: int, enc: bytes) -> Any:
    """Deserialize the provided value."""

    if func := DESERIALIZE_MAP.get(type):
        # Handle single types, treat binary as one to get a neat bytes object
        if count == 1 or type == c_rpm.TagType.BIN:
            return func(enc, 1)

        # Handle string arrays
        if count > 1 and type == c_rpm.TagType.STRING_ARRAY:
            return func(enc, count)

        # Handle implicit arrays (count > 1 and not string array)
        buf = BytesIO(enc)
        return [func(inp, 1) for _ in range(count) if (inp := buf.read(size))]

    raise ValueError(f"Unknown TagType {type!s} with value {enc!r}")
