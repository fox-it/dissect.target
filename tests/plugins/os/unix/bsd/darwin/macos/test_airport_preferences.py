from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.airport_preferences import AirportPreferencesPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "com.apple.airport.preferences.plist",
    ],
)
def test_aiport_preferences(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"/Library/Preferences/SystemConfiguration/{test_file}", data_file)
    entry = fs_unix.get(f"/Library/Preferences/SystemConfiguration/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(AirportPreferencesPlugin)

        results = list(target_unix.airport_preferences())
        assert len(results) == 1

        assert results[0].counter == 2
        assert results[0].device_uuid == "0527924E-C5F8-4703-BDDC-9283B6E9FDAE"
        assert results[0].version == 7200
        assert results[0].preferred_order == "[]"
        assert results[0].source == "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
