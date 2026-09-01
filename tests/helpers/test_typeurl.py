from __future__ import annotations

from dissect.target.helpers.typeurl import unmarshal_any_json
from tests._utils import absolute_path


def test_typeurl_unmarshal_json() -> None:
    """Test if we can umarshal a typeurl any json object."""
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
