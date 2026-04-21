from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.installation_history import InstallationHistoryPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "InstallHistory.plist",
    ],
)
def test_aiport_preferences(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"/Library/Receipts/{test_file}", data_file)
    entry = fs_unix.get(f"/Library/Receipts/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(InstallationHistoryPlugin)

        results = list(target_unix.installation_history())
        assert len(results) == 1

        assert results[0].date == datetime(2026, 3, 25, 14, 7, 11, tzinfo=tz)
        assert results[0].display_name == "macOS 26.4"
        assert results[0].display_version == "26.4"
        assert results[0].process_name == "softwareupdated"
        assert results[0].source == "/Library/Receipts/InstallHistory.plist"
