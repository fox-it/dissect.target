from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.time_machine import TimeMachinePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_file",
    [
        "com.apple.TimeMachine.plist",
    ],
)
def test_aiport_preferences(test_file: str, target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/{test_file}")
    fs_unix.map_file(f"/Library/Preferences/{test_file}", data_file)

    target_unix.add_plugin(TimeMachinePlugin)

    results = list(target_unix.time_machine())
    assert len(results) == 2

    assert results[0].last_destination_id is None
    assert results[0].auto_backup_interval == 3600
    assert results[0].host_uuids == ["543ECB5B-2A5B-5E41-8FE8-D1A0E9FF5F7E"]
    assert not results[0].requires_ac_power
    assert results[0].suspend_helper_activity_timestamp == datetime(1995, 6, 11, 7, 40, 38, tzinfo=timezone.utc)
    assert results[0].backup_alias is not None
    assert isinstance(results[0].backup_alias, (bytes, bytearray))
    assert results[0].preferences_version == 6
    assert results[0].auto_backup == 1
    assert results[0].last_activity_backup == datetime(2026, 5, 11, 13, 7, 9, tzinfo=timezone.utc)
    assert results[0].source == "/Library/Preferences/com.apple.TimeMachine.plist"

    assert results[1].destination_uuids == ["6041C936-15F2-436F-9320-0BA84E6F27BC"]
    assert results[1].last_known_volume_name == "Backups of Testbook1\u2019s MacBook Pro"
    assert results[1].result == 0
    assert results[1].filesystem_type_name == "apfs"
    assert results[1].last_known_encryption_state == "Encrypted"
    assert results[1].stable_local_snapshot_date == datetime(2026, 6, 11, 7, 41, 52, tzinfo=timezone.utc)
    assert results[1].inheritance_decision == 0
    assert results[1].destination_id == "D660D3DA-6567-49A9-A133-02E95682CFFE"
    assert results[1].bytes_used == 385024
    assert results[1].destination_version == 23
    assert results[1].health_check_decision == 0
    assert results[1].smb_conversion_state == 0
    assert results[1].attempt_dates == [datetime(2026, 6, 11, 7, 41, 45, 410654, tzinfo=timezone.utc)]
    assert results[1].bytes_available == 924195943880
    assert results[1].source == "/Library/Preferences/com.apple.TimeMachine.plist"
