from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

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
    entry = fs_unix.get(f"/var/db/gkopaque.bundle/Contents/Resources/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(GatekeeperOpaqueConfigurationPlugin)

        results = list(target_unix.gkopaque())

        assert len(results) == 74247

        assert results[0].table == "whitelist"
        assert (
            results[0].current
            == "\x00\x03'\udcec\udce1\udcfbZ'\udcb5\udcf5\udcc5\x1a\x00\udc99\x00\udcb1\udce4\udc85K\udcb7"
        )
        assert results[0].opaque == "\udccb\udce5k\udc97\udc84\udc97N\n\x1c\x01Y\udcc4\x1f9+wB\x1bM#"
        assert results[0].source == "/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db"

        assert results[-1].table == "conditions"
        assert results[-1].label == "google chrome (canary)"
        assert results[-1].weight == 300
        assert results[-1].conditions_source == "EQHXZ8M8AV"
        assert results[-1].identifier == "com.google.Chrome.canary"
        assert results[-1].version is None
        assert results[-1].conditions == "{errors=[-67013]}"
        assert results[-1].source == "/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db"
