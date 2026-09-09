from __future__ import annotations

from json import JSONDecodeError

import pytest

from dissect.target.helpers.typeurl import unmarshal_any, unmarshal_any_json
from tests._utils import absolute_path


def test_typeurl_unmarshal_json() -> None:
    """Test if we can umarshal a typeurl any json object."""
    path, obj = unmarshal_any(b"\x00\x03foo\x00\x03bar")
    assert path == "foo"
    assert obj == b"bar"

    raw = absolute_path("_data/helpers/typeurl.bin").read_bytes()
    path, obj = unmarshal_any_json(raw)
    assert path == "types.containerd.io/opencontainers/runtime-spec/1/Spec"
    assert isinstance(obj, dict)
    assert obj.get("ociVersion") == "1.3.0"
    assert obj["process"]["env"] == [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOSTNAME=5fc9c48c9ee7",
        "TERM=xterm",
    ]


@pytest.mark.parametrize(
    ("input", "exception", "match"),
    [
        (None, ValueError, r"Expecting value\: line 1 column 1 \(char 0\)"),
        (b"", ValueError, r"Invalid typeurl structure\: Read 0 bytes\, but expected 1"),
        (b"\x00\x03foo\x00\x03bar", JSONDecodeError, r"Expecting value: line 1 column 1 \(char 0\)"),
    ],
)
def test_typeurl_unmarshal_json_invalid(input: bytes, exception: type[Exception], match: str) -> None:
    """Test if the unmarshal function behaves when provided with invalid data."""
    with pytest.raises(exception, match=match):
        unmarshal_any_json(input)
