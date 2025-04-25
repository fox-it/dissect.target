from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.log.lastlog import LastLogPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_lastlog_plugin(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    data_file = absolute_path("_data/plugins/os/unix/log/lastlog/lastlog")
    fs_linux.map_file("/var/log/lastlog", data_file)

    target_linux.add_plugin(LastLogPlugin)

    results = list(target_linux.lastlog())
    assert len(results) == 1

    assert results[0].ts == datetime(2021, 12, 8, 16, 14, 6, tzinfo=timezone.utc)
    assert results[0].uid == 1001
    assert results[0].ut_user is None
    assert results[0].ut_host == "127.0.0.1"
    assert results[0].ut_tty == "pts/0"
