from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.muicache import MuiCachePlugin


def test_muicache_plugin(target_win_users, hive_hku):
    # NT >= 6.0
    muicache_shell_key = VirtualKey(
        hive_hku,
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
    )
    muicache_shell_key.add_value("LangID", VirtualValue(hive_hku, "LangID", b"\t\x04"))
    muicache_shell_key.add_value(
        "C:\\Windows\\System32\\fsquirt.exe.FriendlyAppName",
        VirtualValue(hive_hku, "C:\\Windows\\System32\\fsquirt.exe.FriendlyAppName", "fsquir"),
    )
    muicache_shell_key.add_value(
        "C:\\Windows\\System32\\fsquirt.test.exe.ApplicationCompany",
        VirtualValue(hive_hku, "C:\\Windows\\System32\\fsquirt.test.exe.ApplicationCompany", "fsquir"),
    )

    # NT >= 6.0 (subkey)
    muicache_key = VirtualKey(
        hive_hku,
        "Software\\Classes\\Local Settings\\MuiCache\\35\\52C64B7E",
    )
    muicache_key.add_value(
        "@C:\\Windows\\system32\\wsecedit.dll,-718",
        VirtualValue(hive_hku, "@C:\\Windows\\system32\\wsecedit.dll,-718", "Local Security Policy"),
    )

    # NT < 6.0
    muicache_shellnoroam_key = VirtualKey(
        hive_hku,
        "Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",
    )
    muicache_shellnoroam_key.add_value(
        "@C:\\WINDOWS\\inf\\unregmp2.exe,-4",
        VirtualValue(hive_hku, "@C:\\WINDOWS\\inf\\unregmp2.exe,-4", "Windows Media Player"),
    )

    hive_hku.map_key(muicache_shell_key.path, muicache_shell_key)
    hive_hku.map_key(muicache_key.path, muicache_key)
    hive_hku.map_key(muicache_shellnoroam_key.path, muicache_shellnoroam_key)

    target_win_users.add_plugin(MuiCachePlugin)

    results = list(target_win_users.muicache())

    assert len(results) == 4
    assert results[0].index == 1
    assert results[0].name == "FriendlyAppName"
    assert results[0].value == "fsquir"
    assert str(results[0].path) == "C:\\Windows\\System32\\fsquirt.exe"
    assert results[1].index == 2
    assert results[1].name == "ApplicationCompany"
    assert results[1].value == "fsquir"
    assert str(results[1].path) == "C:\\Windows\\System32\\fsquirt.test.exe"
    assert results[2].index == 0
    assert results[2].name is None
    assert results[2].value == "Local Security Policy"
    assert str(results[2].path) == "@C:\\Windows\\system32\\wsecedit.dll"
    assert results[3].index == 0
    assert results[3].name is None
    assert results[3].value == "Windows Media Player"
    assert str(results[3].path) == "@C:\\WINDOWS\\inf\\unregmp2.exe"
