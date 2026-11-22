from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.logs.fsck_apfs_log import FsckAPFSLogPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "fsck_apfs.log",
    ],
)
def test_fsck_apfs_log(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    tz = timezone.utc
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/logs/{test_file}")
    fs_unix.map_file(f"/var/log/{test_file}", data_file)

    target_unix.add_plugin(FsckAPFSLogPlugin)

    results = list(target_unix.fsck_apfs_log())
    assert len(results) == 3

    assert results[0].ts == datetime(2026, 5, 4, 4, 23, 21, tzinfo=tz)
    assert results[0].disk_path == "/dev/rdisk1s1"
    assert results[0].message == "fsck_apfs started at Mon May  4 04:23:21 2026"
    assert results[0].source == "/var/log/fsck_apfs.log"

    assert results[1].ts is None
    assert results[1].disk_path == "/dev/rdisk1s1"
    assert results[1].message == "error: container /dev/rdisk1 is mounted with write access; please re-run with -l."
    assert results[1].source == "/var/log/fsck_apfs.log"

    assert results[-1].ts == datetime(2026, 5, 4, 4, 23, 21, tzinfo=tz)
    assert results[-1].disk_path == "/dev/rdisk1s1"
    assert results[-1].message == "fsck_apfs completed at Mon May  4 04:23:21 2026"
    assert results[-1].source == "/var/log/fsck_apfs.log"
