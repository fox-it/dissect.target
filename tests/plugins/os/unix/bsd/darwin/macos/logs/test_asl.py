from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.logs.asl import ASLPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        ("2026.05.06.G80.asl"),
    ],
)
def test_system_log(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    stat_results = []

    entries = []
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/logs/{test_file}")
    fs_unix.map_file(f"/var/log/asl/{test_file}", data_file)
    entry = fs_unix.get(f"/var/log/asl/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    entries.append(entry)
    stat_results.append(stat_result)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
    ):
        target_unix.add_plugin(ASLPlugin)
        results = list(target_unix.asl())
        results.sort(key=lambda r: r.source)

        assert len(results) == 11

        assert results[0].ts == datetime(2026, 5, 6, 7, 45, 10, tzinfo=tz)
        assert results[0].priority_level == 5
        assert results[0].pid == 121
        assert results[0].asl_host == "localhost"
        assert results[0].sender == "syslogd"
        assert results[0].facility == "syslog"
        assert results[0].message == (
            "Configuration Notice:\n"
            'ASL Module "com.apple.cdscheduler" claims selected messages.\n'
            "Those messages may not appear in standard system log files or in the ASL database."
        )
        assert results[0].source == "/var/log/asl/2026.05.06.G80.asl"

        assert results[1].ts == datetime(2026, 5, 6, 7, 45, 10, tzinfo=tz)
        assert results[1].priority_level == 5
        assert results[1].pid == 121
        assert results[1].asl_host == "localhost"
        assert results[1].sender == "syslogd"
        assert results[1].facility == "syslog"
        assert results[1].message == (
            "Configuration Notice:\n"
            'ASL Module "com.apple.install" claims selected messages.\n'
            "Those messages may not appear in standard system log files or in the ASL database."
        )
        assert results[1].source == "/var/log/asl/2026.05.06.G80.asl"

        assert results[-1].ts == datetime(2026, 5, 6, 11, 50, 20, tzinfo=tz)
        assert results[-1].priority_level == 5
        assert results[-1].pid == 122
        assert results[-1].asl_host == "localhost"
        assert results[-1].sender == "syslogd"
        assert results[-1].facility == "syslog"
        assert results[-1].message == (
            "Configuration Notice:\n"
            'ASL Module "com.apple.eventmonitor" claims selected messages.\n'
            "Those messages may not appear in standard system log files or in the ASL database."
        )
        assert results[-1].source == "/var/log/asl/2026.05.06.G80.asl"
