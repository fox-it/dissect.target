from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.activitiescache import ActivitiesCachePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_windows_activitiescache_10_22H2(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can parse an ActivitiesCache.db file from Windows 10 22H2 correctly."""
    fs_win.map_file(
        "Users/John/AppData/Local/ConnectedDevicesPlatform/L.John/ActivitiesCache.db",
        str(absolute_path("_data/plugins/os/windows/activitiescache/ActivitiesCache.db")),
    )

    target_win_users.add_plugin(ActivitiesCachePlugin)

    records = list(target_win_users.activitiescache())

    assert len(records) == 22

    assert records[0].start_time == datetime(2025, 3, 4, 10, 28, 20, tzinfo=timezone.utc)
    assert not records[0].end_time
    assert records[0].last_modified_time == datetime(2025, 3, 4, 10, 28, 20, tzinfo=timezone.utc)
    assert records[0].last_modified_on_client == datetime(2025, 3, 4, 10, 28, 20, tzinfo=timezone.utc)
    assert not records[0].original_last_modified_on_client
    assert records[0].expiration_time == datetime(2032, 3, 2, 10, 28, 20, tzinfo=timezone.utc)
    assert records[0].activity_id == "c3d8d9afdec8125895bcc9348387ade1"
    assert (
        records[0].app_id
        == '[{"application":"microsoft.default.default","platform":"data_boundary"},{"application":"","platform":"packageId"},{"application":"","platform":"alternateId"}]'  # noqa: E501
    )
    assert not records[0].enterprise_id
    assert (
        records[0].app_activity_id
        == "default$windows.data.bluelightreduction.settings|windows.data.bluelightreduction.settings"
    )
    assert not records[0].group_app_activity_id
    assert records[0].group == "default$windows.data.bluelightreduction.settings"
    assert records[0].activity_type == 11
    assert records[0].activity_status == 1
    assert records[0].activity_priority == 3
    assert not records[0].match_id
    assert records[0].etag == 1
    assert records[0].tag == "windows.data.bluelightreduction.settings"
    assert records[0].is_local_only
    assert records[0].created_in_cloud == datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert records[0].platform_device_id == "TNlommUcFlcw1lY+F+z4Sc57ss7UZKgX9GKxBTcbSYE="
    assert records[0].package_id_hash == "ZZzI03ZhPBD1Dfj2GvrCeHMuMjZ9FnVlYIDK+kZzTu0="
    assert records[0].payload == "Q0IBAMoUDhUAyh4OBwDKMgDKPAAA"
    assert not records[0].original_payload
    assert not records[0].clipboard_payload
    assert records[0].source == "C:\\Users\\John\\AppData\\Local\\ConnectedDevicesPlatform\\L.John\\ActivitiesCache.db"
    assert records[0].username == "John"
