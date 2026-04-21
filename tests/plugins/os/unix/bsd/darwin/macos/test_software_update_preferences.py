from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.software_update_preferences import SoftwareUpdatePreferencesPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "com.apple.SoftwareUpdate.plist",
    ],
)
def test_software_update_preferences(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"/Library/Preferences/{test_file}", data_file)
    entry = fs_unix.get(f"/Library/Preferences/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(SoftwareUpdatePreferencesPlugin)

        results = list(target_unix.software_update_preferences())
        assert len(results) == 1

        assert results[0].last_result_code == 2
        assert results[0].last_attempt_system_version == "26.4 (25E246)"
        assert results[0].last_attempt_build_version == "26.4 (25E246)"
        assert results[0].automatic_download
        assert results[0].automatically_install_macos_updates
        assert results[0].critical_update_install
        assert results[0].config_data_install
        assert results[0].recommended_updates == []
        assert results[0].splat_enabled
        assert not results[0].post_logout_notification
        assert results[0].last_recommended_major_os_bundle_id == ""
        assert results[0].primary_languages == ["en", "en-US"]
        assert results[0].last_successful_date == datetime(2026, 3, 25, 14, 11, 47, tzinfo=tz)
        assert results[0].last_full_successful_date == datetime(2026, 3, 25, 14, 11, 47, tzinfo=tz)
        assert results[0].source == "/Library/Preferences/com.apple.SoftwareUpdate.plist"
