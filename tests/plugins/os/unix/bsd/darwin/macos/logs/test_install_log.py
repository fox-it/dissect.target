from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.logs.install_log import InstallLogPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "install.log",
    ],
)
def test_install_log(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/logs/{test_file}")
    fs_unix.map_file(f"/var/log/{test_file}", data_file)

    entry = fs_unix.get(f"/var/log/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(InstallLogPlugin)

        results = list(target_unix.install_log())
        assert len(results) == 3

        assert results[0].ts == datetime(2026, 3, 25, 14, 6, 59, tzinfo=tz)
        assert results[0].host == "localhost"
        assert results[0].component == "Installer"
        assert results[0].message == "Progress[57]: Progress UI App Starting"
        assert results[0].source == "/var/log/install.log"

        assert results[1].ts == datetime(2026, 3, 25, 14, 7, tzinfo=tz)
        assert results[1].host == "localhost"
        assert results[1].component == "Installer"
        assert results[1].message == "Progress[57]: Logging also using os_log, installerProgressLog = 0xc6501c080"
        assert results[1].source == "/var/log/install.log"

        assert results[-1].ts == datetime(2026, 3, 25, 15, 18, 58, tzinfo=tz)
        assert results[-1].host == "users-Virtual-Machine"
        assert results[-1].component == "loginwindow[1042]:"
        assert results[-1].message == "+[SUOSULoginCredentialPolicy currentLoginCredentialPolicy] = 0"
        assert results[-1].source == "/var/log/install.log"
