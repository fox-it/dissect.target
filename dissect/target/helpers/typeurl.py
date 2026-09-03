from __future__ import annotations

import json

from dissect.cstruct import cstruct

from dissect.target.helpers.protobuf import ProtobufVarint

typeurl_def = """
struct any {
    uint8       header;
    varint      path_size;
    char        path[path_size];
    varint      unknown;
    varint      value_size;
    char        value[value_size];
};
"""
c_typeurl = cstruct(endian=">")
c_typeurl.add_custom_type("varint", ProtobufVarint, size=None, alignment=1, signed=False)
c_typeurl.load(typeurl_def, compiled=False)


def unmarshal_any(raw: bytes) -> tuple[str, bytes]:
    """Unmarshal a typeurl any structure.

    Returns:
        Tuple of bytes (path, value)

    References:
        - https://github.com/containerd/typeurl
    """
    struct = c_typeurl.any(raw)
    return struct.path.decode(), struct.value


def unmarshal_any_json(raw: bytes) -> tuple[str, dict]:
    """Attempt to unmarshal a typeurl any structure to a JSON dict.

    Returns: tuple of path (str) and JSON object (dict)
    """
    path, value = unmarshal_any(raw)
    try:
        return path, json.loads(value.decode())
    except UnicodeDecodeError as e:
        raise ValueError("Failed to decode typeurl structure %s: %s", path, e) from e
