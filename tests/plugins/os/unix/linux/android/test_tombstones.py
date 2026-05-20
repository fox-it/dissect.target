from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.android.tombstones import AndroidTombstonesPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_android_tombstone(target_android: Target, fs_android: VirtualFilesystem) -> None:
    """Test if a tombstone file is found and read correctly."""
    fs_android.map_file(
        "/data/tombstones/tombstone_01", absolute_path("_data/plugins/os/unix/linux/android/system/tombstone_01")
    )

    target_android.add_plugin(AndroidTombstonesPlugin)
    records = list(target_android.tombstones())

    assert records[0].ts == datetime.datetime.fromisoformat("2026-05-04 15:30:00.123456+00:00")
    assert records[0].app_id == "dev.serwin.AnarchRE_3"  # public domain DOOM ftw
    assert records[0].command.executable == "dev.serwin.AnarchRE_3"
    assert records[0].pid == 1337
    assert records[0].tid == 314
    assert records[0].signal_uid == 10000
    assert records[0].signal_pid == 67
    assert records[0].process_uptime_seconds == 10
    assert records[0].source == "/data/tombstones/tombstone_01"
