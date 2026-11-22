from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.gkopaque import GatekeeperOpaqueConfigurationPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "gkopaque.db",
    ],
)
def test_gkopaque(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"/var/db/gkopaque.bundle/Contents/Resources/{test_file}", data_file)

    target_unix.add_plugin(GatekeeperOpaqueConfigurationPlugin)

    results = list(target_unix.gkopaque())

    assert len(results) == 74247

    assert results[0].table == "whitelist"
    assert results[0].current == b"\x00\x03'\xec\xe1\xfbZ'\xb5\xf5\xc5\x1a\x00\x99\x00\xb1\xe4\x85K\xb7"
    assert results[0].opaque == b"\xcb\xe5k\x97\x84\x97N\n\x1c\x01Y\xc4\x1f9+wB\x1bM#"
    assert results[0].source == "/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db"

    assert results[-1].table == "conditions"
    assert results[-1].label == "google chrome (canary)"
    assert results[-1].weight == 300
    assert results[-1].conditions_source == "EQHXZ8M8AV"
    assert results[-1].identifier == "com.google.Chrome.canary"
    assert results[-1].version is None
    assert results[-1].conditions == "{errors=[-67013]}"
    assert results[-1].source == "/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db"
