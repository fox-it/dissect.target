from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.linux.debian.apt import AptPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "history.log",
        "history.log.1.gz",
        "history.log.1.bz2",
    ],
)
def test_apt_logs(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/linux/debian/apt/{test_file}")
    fs_unix.map_file(f"/var/log/apt/{test_file}", data_file)
    target_unix.add_plugin(AptPlugin)

    results = list(target_unix.apt.logs())
    assert len(results) == 18

    for record in results:
        assert record.package_manager == "apt"

    assert results[0].ts == datetime(2022, 9, 2, 6, 36, 31, tzinfo=tz)
    assert results[0].operation == "update"
    assert results[0].package_name == "libcurl4:amd64 (7.68.0-1ubuntu2.12, 7.68.0-1ubuntu2.13)"
    assert results[0].command == "/usr/bin/unattended-upgrade"
    assert results[0].requested_by_user is None

    assert results[-1].ts == datetime(2022, 9, 7, 7, 48, 28, tzinfo=tz)
    assert results[-1].operation == "update"
    assert results[-1].package_name == "linux-generic:amd64 (5.4.0.125.126, 5.4.0.126.127)"
    assert results[-1].command == "/usr/bin/unattended-upgrade"
    assert results[-1].requested_by_user == "user (1000)"
