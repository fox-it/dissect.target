from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.logs.systemlog import SystemLogPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "system.log",
    ],
)
def test_system_log(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/logs/{test_file}")
    fs_unix.map_file(f"/var/log/{test_file}", data_file)

    entry = fs_unix.get(f"/var/log/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(SystemLogPlugin)

        results = list(target_unix.systemlog())
        assert len(results) == 3

        assert results[0].ts == datetime(1900, 3, 25, 7, 6, 57, tzinfo=tz)
        assert results[0].host == "localhost"
        assert results[0].component == "bootlog[0]:"
        assert results[0].message == "BOOT_TIME 1774447617 0"
        assert results[0].source == "/var/log/system.log"

        assert results[1].ts == datetime(1900, 3, 25, 7, 7, tzinfo=tz)
        assert results[1].host == "localhost"
        assert results[1].component == "syslogd[60]:"
        assert results[1].message == (
            "Configuration Notice:\n\t"
            'ASL Module "com.apple.cdscheduler" claims selected messages.\n\t'
            "Those messages may not appear in standard system log files or in the ASL database."
        )
        assert results[1].source == "/var/log/system.log"

        assert results[-1].ts == datetime(1900, 3, 25, 16, 19, 5, tzinfo=tz)
        assert results[-1].host == "users-Virtual-Machine"
        assert results[-1].component == "shutdown[1785]:"
        assert results[-1].message == "SHUTDOWN_TIME: 1774451945 577079"
        assert results[-1].source == "/var/log/system.log"
