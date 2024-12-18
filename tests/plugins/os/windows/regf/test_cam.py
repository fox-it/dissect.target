from dissect.util.ts import wintimestamp

from dissect.target import Target
from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.cam import CamPlugin


def test_cam(target_win_users: Target, hive_hku: VirtualHive):
    cam_key = VirtualKey(
        hive_hku,
        "Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam",
    )

    microsoft_camera_key = VirtualKey(hive_hku, f"{hive_hku}\\{cam_key.path}\\Microsoft.WindowsCamera_8wekyb3d8bbwe")
    microsoft_camera_key.add_value("LastUsedTimeStart", VirtualValue(hive_hku, "LastUsedTimeStart", 133784711366495858))
    microsoft_camera_key.add_value("LastUsedTimeStop", VirtualValue(hive_hku, "LastUsedTimeStop", 133784711515887950))

    firefox_key = VirtualKey(hive_hku, f"{hive_hku}\\{cam_key.path}\\C:#Program Files#Mozilla Firefox#firefox.exe")
    firefox_key.add_value("LastUsedTimeStart", VirtualValue(hive_hku, "LastUsedTimeStart", 133788466426086184))
    firefox_key.add_value("LastUsedTimeStop", VirtualValue(hive_hku, "LastUsedTimeStop", 133788466774490036))

    nonpackaged_key = VirtualKey(hive_hku, f"{hive_hku}\\{cam_key.path}\\NonPackaged")
    nonpackaged_key.add_subkey("C:#Program Files#Mozilla Firefox#firefox.exe", firefox_key)

    cam_key.add_subkey(microsoft_camera_key.name, microsoft_camera_key)
    cam_key.add_subkey(nonpackaged_key.name, nonpackaged_key)

    hive_hku.map_key(cam_key.path, cam_key)

    target_win_users.add_plugin(CamPlugin)
    results = list(target_win_users.cam())

    assert len(results) == 2
    assert results[0].device == "webcam"
    assert results[0].app_name == "Microsoft.WindowsCamera_8wekyb3d8bbwe"
    assert results[0].last_used_time_start == wintimestamp(133784711366495858)
    assert results[0].last_used_time_stop == wintimestamp(133784711515887950)
    assert results[1].device == "webcam"
    assert results[1].app_name == "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
    assert results[1].last_used_time_start == wintimestamp(133788466426086184)
    assert results[1].last_used_time_stop == wintimestamp(133788466774490036)
