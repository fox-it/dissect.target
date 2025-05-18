from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.wua_history import WuaHistoryPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_wua_history_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    wua_history_dir = absolute_path("_data/plugins/os/windows/wua_history/DataStore.edb.gz")
    fs_win.map_file("Windows/SoftwareDistribution/DataStore/DataStore.edb", wua_history_dir, compression="gzip")
    target_win.add_plugin(WuaHistoryPlugin)

    records = list(target_win.wua_history())
    record = records[0]

    assert len(records) == 80
    assert record.ts == datetime(2024, 7, 13, 16, 49, 9, 0, tzinfo=timezone.utc)
    assert record.id_event == 80
    assert record.status == 1
    assert record.status_mapped == "Success"
    assert record.server_selection == 2
    assert record.server_selection_mapped == "ssWindowsUpdate"
    assert record.mapped_result == "0x0"
    assert record.mapped_result_string == "Success"
    assert record.mapped_result_description == "Success"
    assert record.unmapped_result == "0x0"
    assert record.unmapped_result_string == "Success"
    assert record.unmapped_result_description == "Success"
    assert record.update_id == "71156214-2cb8-4c44-b11c-3ec1a0366f55"
    assert record.server_id == "9482f4b4-e343-43b6-b170-9a65bc822c77"
    assert record.server_id_mapped == "Windows Update"
    assert record.flags == 1
    assert record.client_id == "UpdateOrchestrator"
    assert (
        record.title
        == "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.415.74.0) - Current "
        "Channel (Broad)"
    )
    assert (
        record.description
        == "Install this update to revise the files that are used to detect viruses, spyware, and other potentially "
        "unwanted software. Once you have installed this item, it cannot be removed."
    )
    assert record.support_url == "https://go.microsoft.com/fwlink/?LinkId=52661"
    assert record.categories == "Microsoft Defender Antivirus"
    assert record.more_info_url == "https://go.microsoft.com/fwlink/?linkid=2007160"
    assert record.id_user == 0
    assert record.is_service_is_additional == "False"
    assert record.classification == "e0789628-ce08-4437-be74-2495b842f43b"
    assert record.classification_mapped == "DefinitionUpdates"
    assert record.kb == "KB2267602"
