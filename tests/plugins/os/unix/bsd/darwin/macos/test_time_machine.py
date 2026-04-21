from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.time_machine import TimeMachinePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "com.apple.TimeMachine.plist",
    ],
)
def test_aiport_preferences(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"/Library/Preferences/{test_file}", data_file)
    entry = fs_unix.get(f"/Library/Preferences/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(TimeMachinePlugin)

        results = list(target_unix.time_machine())
        assert len(results) == 1

        assert results[0].preferences_version == 6
        assert results[0].source == "/Library/Preferences/com.apple.TimeMachine.plist"
