from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.fs_events import FSEventsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "fc0077112a6fa939",
    ],
)
def test_fs_events(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"System/Volumes/Data/.fseventsd/{test_file}", data_file)

    target_unix.add_plugin(FSEventsPlugin)

    results = list(target_unix.fs_events())

    assert len(results) == 2730

    assert results[0].path == "Library/Caches/com.apple.amsengagementd.classicdatavault"
    assert results[0].event_id == 18158644613167937534
    assert results[0].event_flags == ["ItemCreated", "Unknown(0x01000000)"]
    assert results[0].node_id == 634146
    assert results[0].source == "/System/Volumes/Data/.fseventsd/fc0077112a6fa939"

    assert results[1].path == "Library/Caches/com.apple.amsengagementd.classicdatavault/analytics/jetpackByteCode"
    assert results[1].event_id == 18158644613167937776
    assert results[1].event_flags == ["EventIdsWrapped", "HistoryDone", "Unknown(0x00800000)"]
    assert results[1].node_id == 1672774
    assert results[1].source == "/System/Volumes/Data/.fseventsd/fc0077112a6fa939"

    assert results[-1].path == "private/var/root/Library/Preferences/com.apple.xpc.activity2.plist"
    assert results[-1].event_id == 18158644613167949036
    assert results[-1].event_flags == ["EventIdsWrapped", "Unknown(0x00800000)"]
    assert results[-1].node_id == 1663163
    assert results[-1].source == "/System/Volumes/Data/.fseventsd/fc0077112a6fa939"
