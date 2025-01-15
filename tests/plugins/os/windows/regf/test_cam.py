from dissect.util.ts import wintimestamp

from dissect.target import Target
from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.cam import CamPlugin


def test_cam(target_win_users: Target, hive_hku: VirtualHive, hive_hklm: VirtualHive) -> None:
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
