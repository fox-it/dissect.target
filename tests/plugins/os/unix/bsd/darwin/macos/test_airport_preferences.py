from __future__ import annotations

from typing import TYPE_CHECKING

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

    target_unix.add_plugin(AirportPreferencesPlugin)

    results = list(target_unix.airport_preferences())
    assert len(results) == 1

    assert results[0].counter == 2
    assert results[0].device_uuid == "0527924E-C5F8-4703-BDDC-9283B6E9FDAE"
    assert results[0].version_number == 7200
    assert results[0].preferred_order == []
    assert results[0].source == "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
