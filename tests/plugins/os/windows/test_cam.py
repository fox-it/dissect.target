from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util.ts import wintimestamp

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.cam import CamPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_cam_history(target_win_users: Target, hive_hklm: VirtualHive, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "ProgramData/Microsoft/Windows/CapabilityAccessManager/CapabilityAccessManager.db",
        absolute_path("_data/plugins/os/windows/cam/CapabilityAccessManager.db"),
    )

    hklm_cam_key = VirtualKey(
        hive_hklm,
        "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\CapabilityUsageHistory",
    )

    database_root_value = "C:\\ProgramData\\Microsoft\\Windows\\CapabilityAccessManager"
    hklm_cam_key.add_value("DatabaseRoot", VirtualValue(hive_hklm, "DatabaseRoot", database_root_value))

    hive_hklm.map_key(hklm_cam_key.path, hklm_cam_key)

    target_win_users.add_plugin(CamPlugin)
    results = list(target_win_users.cam())

    assert len(results) == 3

    # Record windows/cam/usagehistory - NonPackagedUsageHistory
    assert results[0].last_used_time_stop == wintimestamp(133885054906926593)
    assert results[0].last_used_time_start == wintimestamp(133885044556858623)
    assert results[0].duration == 1035
    assert results[0].package_type == "NonPackagedUsageHistory"
    assert results[0].capability == "microphone"
    assert results[0].file_id == "0000f0bfca16305374262ad1919c258deba64fc25006"
    assert results[0].file_id_hash.sha1 == "f0bfca16305374262ad1919c258deba64fc25006"
    assert results[0].access_blocked == "0"
    assert results[0].program_id == "00001495bc9d3674a3db3bbed7de63ca0f920000ffff"
    assert results[0].package_family_name is None
    assert results[0].access_guid is None
    assert results[0].label == "2"
    assert results[0].app_name == "Microsoft Edge"
    assert results[0].binary_full_path == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    assert results[0].service_name is None
    assert results[0].username is None

    # Record windows/cam/usagehistory - NonPackagedUsageHistory
    assert results[1].last_used_time_stop == wintimestamp(133884984261774039)
    assert results[1].last_used_time_start == wintimestamp(133884984204276055)
    assert results[1].duration == 5
    assert results[1].package_type == "PackagedUsageHistory"
    assert results[1].capability == "microphone"
    assert results[1].file_id is None
    assert results[1].file_id_hash.sha1 is None
    assert results[1].access_blocked == "0"
    assert results[1].program_id is None
    assert results[1].package_family_name == "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe"
    assert results[1].app_name == "Sound Recorder"
    assert results[1].access_guid is None
    assert results[1].label == "2"
    assert results[1].app_name == "Sound Recorder"
    assert results[1].binary_full_path is None
    assert results[1].service_name is None
    assert results[1].username is None

    # Record windows/cam/identityrelationshiphistory - NonPackagedIdentityRelationship
    assert results[2].last_observed_time == wintimestamp(133892048101847846)
    assert results[2].file_id == "0000565c728f1a97551d85db2e788c69e0d8a18ea777"
    assert results[2].file_id_hash.sha1 == "565c728f1a97551d85db2e788c69e0d8a18ea777"
    assert results[2].program_id == "0000d44ffb9f3c146e6da82376ed56489aff0000ffff"
    assert results[2].binary_full_path == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"

    # Record windows/cam/globalprompthistory - NonPackagedGlobalPromptHistory
    # No test data for this record type.


def test_cam_registry(target_win_users: Target, hive_hku: VirtualHive, hive_hklm: VirtualHive) -> None:
    hku_cam_key = VirtualKey(
        hive_hku,
        "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam",
    )

    hklm_cam_key = VirtualKey(
        hive_hklm,
        "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone",
    )

    microsoft_camera_key = VirtualKey(
        hive_hku, f"{hive_hku}\\{hku_cam_key.path}\\Microsoft.WindowsCamera_8wekyb3d8bbwe"
    )
    microsoft_camera_key.add_value("LastUsedTimeStart", VirtualValue(hive_hku, "LastUsedTimeStart", 133784711366495858))
    microsoft_camera_key.add_value("LastUsedTimeStop", VirtualValue(hive_hku, "LastUsedTimeStop", 133784711515887950))

    firefox_key = VirtualKey(hive_hku, f"{hive_hku}\\{hku_cam_key.path}\\C:#Program Files#Mozilla Firefox#firefox.exe")
    firefox_key.add_value("LastUsedTimeStart", VirtualValue(hive_hku, "LastUsedTimeStart", 133788466426086184))
    firefox_key.add_value("LastUsedTimeStop", VirtualValue(hive_hku, "LastUsedTimeStop", 133788466774490036))

    nonpackaged_key = VirtualKey(hive_hku, f"{hive_hku}\\{hku_cam_key.path}\\NonPackaged")
    nonpackaged_key.add_subkey("C:#Program Files#Mozilla Firefox#firefox.exe", firefox_key)

    python_key = VirtualKey(
        hive_hklm, f"{hive_hklm}\\{hklm_cam_key.path}\\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0"
    )
    python_key.add_value("LastUsedTimeStart", VirtualValue(hive_hklm, "LastUsedTimeStart", 133788466426086163))
    python_key.add_value("LastUsedTimeStop", VirtualValue(hive_hklm, "LastUsedTimeStop", 133788466774490044))

    hku_cam_key.add_subkey(microsoft_camera_key.name, microsoft_camera_key)
    hku_cam_key.add_subkey(nonpackaged_key.name, nonpackaged_key)
    hklm_cam_key.add_subkey(python_key.name, python_key)

    hive_hku.map_key(hku_cam_key.path, hku_cam_key)
    hive_hklm.map_key(hklm_cam_key.path, hklm_cam_key)

    target_win_users.add_plugin(CamPlugin)
    results = list(target_win_users.cam())

    assert len(results) == 3
    assert results[0].device == "webcam"
    assert results[0].app_name == "Microsoft.WindowsCamera_8wekyb3d8bbwe"
    assert results[0].path is None
    assert results[0].last_started == wintimestamp(133784711366495858)
    assert results[0].last_stopped == wintimestamp(133784711515887950)
    assert results[1].device == "webcam"
    assert results[1].app_name == "C:#Program Files#Mozilla Firefox#firefox.exe"
    assert results[1].path == "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
    assert results[1].last_started == wintimestamp(133788466426086184)
    assert results[1].last_stopped == wintimestamp(133788466774490036)
    assert results[2].device == "microphone"
    assert results[2].app_name == "PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0"
    assert results[2].path is None
    assert results[2].last_started == wintimestamp(133788466426086163)
    assert results[2].last_stopped == wintimestamp(133788466774490044)
