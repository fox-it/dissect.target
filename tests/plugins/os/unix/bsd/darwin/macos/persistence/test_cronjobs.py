from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.persistence.cronjobs import CronjobPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            ("one", "two"),
            ("/usr/lib/cron/tabs/user", "/var/at/tabs/user"),
        ),
    ],
)
def test_cronjobs(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/persistence/cronjobs/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(CronjobPlugin)

        results = list(target_unix.cronjobs())

        assert len(results) == 2

        assert results[0].minute == "*"
        assert results[0].hour == "*"
        assert results[0].day == "*"
        assert results[0].month == "*"
        assert results[0].command == "/Users/user/cron_test.sh"
        assert results[0].source == "/usr/lib/cron/tabs/user"

        assert results[1].minute == "*"
        assert results[1].hour == "*"
        assert results[1].day == "*"
        assert results[1].month == "*"
        assert results[1].command == "/Users/user/cron_test.sh"
        assert results[1].source == "/var/at/tabs/user"
