from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.muicache import MuicachePlugin


def test_muicache_plugin(target_win_users, hive_hku):
    muicache_key = VirtualKey(
        hive_hku,
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
    )

    muicache_key.add_value("LangID", VirtualValue(hive_hku, "LangID", b"\t\x04"))
    muicache_key.add_value(
        "C:\\Windows\\System32\\fsquirt.exe.FriendlyAppName",
        VirtualValue(hive_hku, "C:\\Windows\\System32\\fsquirt.exe.FriendlyAppName", "fsquir"),
    )
    muicache_key.add_value(
        "C:\\Windows\\System32\\fsquirt.test.exe.ApplicationCompany",
        VirtualValue(hive_hku, "C:\\Windows\\System32\\fsquirt.test.exe.ApplicationCompany", "fsquir"),
    )

    hive_hku.map_key(muicache_key.path, muicache_key)

    target_win_users.add_plugin(MuicachePlugin)

    results = list(target_win_users.muicache())

    assert len(results) == 2
    assert results[0].index == 1
    assert results[0].name == "FriendlyAppName"
    assert results[0].value == "fsquir"
    assert results[0].path == "C:/Windows/System32/fsquirt.exe"
    assert results[1].index == 2
    assert results[1].name == "ApplicationCompany"
    assert results[1].value == "fsquir"
    assert results[1].path == "C:/Windows/System32/fsquirt.test.exe"