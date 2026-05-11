from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.persistence.at_jobs import AtJobsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "a0000701c43af0",
    ],
)
def test_at_jobs(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/{test_file}")
    fs_unix.map_file(f"/usr/lib/cron/jobs/{test_file}", data_file)
    entry = fs_unix.get(f"/usr/lib/cron/jobs/{test_file}")
    stat_result = entry.stat()
    stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(AtJobsPlugin)

        results = list(target_unix.at_jobs())
        assert len(results) == 1

        assert results[0].queue == "a"
        assert results[0].seq == 7
        assert results[0].execution_time == datetime(2026, 5, 8, 12, 0, 0, tzinfo=tz)
        assert results[0].command == "periodic_test.sh"
        assert results[0].source == "/usr/lib/cron/jobs/a0000701c43af0"
