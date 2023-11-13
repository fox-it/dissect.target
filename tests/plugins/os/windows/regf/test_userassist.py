from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.regf.userassist import UserAssistPlugin

USERASSIST_DATA_VERSION0 = bytes.fromhex(
    "0100000000060000341ad99d3c98d808",
)
USERASSIST_DATA_VERSION3_8 = bytes.fromhex("03e08d0e01000000")
USERASSIST_DATA_VERSION3_16 = bytes.fromhex(
    "000000001a000000d8a599defebbd101",
)
USERASSIST_DATA_VERSION5 = bytes.fromhex(
    "ffffffff000000000000000000000000000080bf000080bf000080bf000080bf"
    "000080bf000080bf000080bf000080bf000080bf000080bfffffffff00000000"
    "0000000000000000"
)


def test_userassist_plugin(target_win_users, hive_hku):
    userassist_key_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    userassist_key = VirtualKey(hive_hku, userassist_key_name)

    version0_key = VirtualKey(hive_hku, "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}")
    version0_count_key = VirtualKey(hive_hku, "Count")
    version0_key.add_subkey("Count", version0_count_key)
    version0_count_key.add_value(
        "Q:\\frghc64.rkr",
        VirtualValue(hive_hku, "Q:\\frghc64.rkr", USERASSIST_DATA_VERSION0),
    )

    version3_key = VirtualKey(hive_hku, "{75048700-EF1F-11D0-9888-006097DEACF9}")
    version3_key.add_value("Version", VirtualValue(hive_hku, "Version", 3))
    version3_count_key = VirtualKey(hive_hku, "Count")
    version3_key.add_subkey("Count", version3_count_key)
    version3_count_key.add_value(
        "Zvpebfbsg.Trgfgnegrq_8jrxlo3q8oojr!Ncc",
        VirtualValue(hive_hku, "Zvpebfbsg.Trgfgnegrq_8jrxlo3q8oojr!Ncc", USERASSIST_DATA_VERSION3_8),
    )
    version3_count_key.add_value(
        "HRZR_PGYFRFFVBA",
        VirtualValue(hive_hku, "HRZR_PGYFRFFVBA", USERASSIST_DATA_VERSION3_16),
    )

    version5_key = VirtualKey(hive_hku, "{CAA59E3C-4792-41A5-9909-6A6A8D32490E}")
    version5_key.add_value("Version", VirtualValue(hive_hku, "Version", 5))
    version5_count_key = VirtualKey(hive_hku, "Count")
    version5_key.add_subkey("Count", version5_count_key)
    version5_count_key.add_value(
        "HRZR_PGYPHNPbhag:pgbe",
        VirtualValue(hive_hku, "HRZR_PGYPHNPbhag:pgbe", USERASSIST_DATA_VERSION5),
    )

    userassist_key.add_subkey(version0_key.name, version0_key)
    userassist_key.add_subkey(version3_key.name, version3_key)
    userassist_key.add_subkey(version5_key.name, version5_key)
    hive_hku.map_key(userassist_key_name, userassist_key)

    target_win_users.add_plugin(UserAssistPlugin)

    results = list(target_win_users.userassist())

    assert len(results) == 4
    assert str(results[0].ts) == "1601-01-01 00:00:00+00:00"
    assert results[0].path == "D:\\setup64.exe"
    assert results[0].number_of_executions is None
    assert results[0].application_focus_count is None
    assert results[0].application_focus_duration is None
    assert str(results[1].ts) == "1601-01-01 00:00:00+00:00"
    assert results[1].path == "Microsoft.Getstarted_8wekyb3d8bbwe!App"
    assert results[1].number_of_executions is None
    assert results[1].application_focus_count is None
    assert results[1].application_focus_duration is None
    assert str(results[2].ts) == "2016-06-01 12:12:30.115376+00:00"
    assert results[2].path == "UEME_CTLSESSION"
    assert results[2].number_of_executions == 26
    assert results[2].application_focus_count is None
    assert results[2].application_focus_duration is None
    assert str(results[3].ts) == "1601-01-01 00:00:00+00:00"
    assert results[3].path == "UEME_CTLCUACount:ctor"
    assert results[3].number_of_executions == 0
    assert results[3].application_focus_count == 0
    assert results[3].application_focus_duration == 0
