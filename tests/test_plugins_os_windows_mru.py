import pytest

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue


@pytest.fixture
def target_win_mru(target_win_users):
    user_details = target_win_users.user_details.find(sid="S-1-5-21-3263113198-3007035898-945866154-1002")

    user_hive = VirtualHive()
    user_hive.filepath = user_details.home_path.joinpath("ntuser.dat")

    # RunMRU
    run_key = VirtualKey(user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
    run_key.add_value("MRUList", VirtualValue(user_hive, "MRUList", "ba"))
    run_key.add_value("a", VirtualValue(user_hive, "a", "cmd\\1"))
    run_key.add_value("b", VirtualValue(user_hive, "b", "\\\\mfs\\1"))

    # RecentDocs
    recentdocs_key = VirtualKey(user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
    recentdocs_key.add_value("MRUListEx", VirtualValue(user_hive, "MRUListEx", b"\x00\x00\x00\x00\xFF\xFF\xFF\xFF"))
    recentdocs_value = bytes.fromhex(
        "55006e007400690074006c0065006400"
        "20002d0020004e006f00740065007000"
        "610064002e0070006400660000008000"
        "320000000000000000000000556e7469"
        "746c6564202d204e6f74657061642e6c"
        "6e6b00005a0008000400efbe00000000"
        "000000002a0000000000000000000000"
        "00000000000000000000000000005500"
        "6e007400690074006c00650064002000"
        "2d0020004e006f007400650070006100"
        "64002e006c006e006b00000026000000"
    )
    recentdocs_key.add_value("0", VirtualValue(user_hive, "0", recentdocs_value))

    # OpenSaveMRU
    opensave_key = VirtualKey(
        user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU"
    )
    opensave_key.add_value("MRUList", VirtualValue(user_hive, "MRUList", "ba"))
    opensave_key.add_value("a", VirtualValue(user_hive, "a", "C:\\path\\to\\a"))
    opensave_key.add_value("b", VirtualValue(user_hive, "b", "C:\\path\\to\\b"))

    opensave_sub_key = VirtualKey(user_hive, opensave_key.path + "\\sub")
    opensave_sub_key.add_value("MRUList", VirtualValue(user_hive, "MRUList", "ba"))
    opensave_sub_key.add_value("a", VirtualValue(user_hive, "a", "C:\\path\\to\\sub\\a"))
    opensave_sub_key.add_value("b", VirtualValue(user_hive, "b", "C:\\path\\to\\sub\\b"))
    opensave_key.add_subkey("*", opensave_sub_key)

    # LastVisitedMRU
    lastvisited_key = VirtualKey(
        user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU"
    )
    lastvisited_key.add_value("MRUList", VirtualValue(user_hive, "MRUList", "ba"))
    value_a = b"\x00\x00".join([x.encode("utf-16-le") for x in ["test_a.exe", "c:\\path\\to\\something\\a", ""]])
    value_b = b"\x00\x00".join([x.encode("utf-16-le") for x in ["test_b.exe", "c:\\path\\to\\something\\b", ""]])
    lastvisited_key.add_value("a", VirtualValue(user_hive, "a", value_a))
    lastvisited_key.add_value("b", VirtualValue(user_hive, "b", value_b))

    # ACMru
    acmru_key = VirtualKey(user_hive, "Software\\Microsoft\\Search Assistant\\ACMru\\5603")
    acmru_key.add_value("000", VirtualValue(user_hive, "000", "value"))
    acmru_key.add_value("001", VirtualValue(user_hive, "001", "value"))

    # Map Network Drive MRU
    networkdrive_key = VirtualKey(
        user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU"
    )
    networkdrive_key.add_value("MRUList", VirtualValue(user_hive, "MRUList", "ba"))
    networkdrive_key.add_value("a", VirtualValue(user_hive, "a", "\\\\path\\to\\a"))
    networkdrive_key.add_value("b", VirtualValue(user_hive, "b", "\\\\path\\to\\b"))

    # Terminal Server Client MRU
    mstsc_key = VirtualKey(user_hive, "Software\\Microsoft\\Terminal Server Client\\Default")
    mstsc_key.add_value("MRU0", VirtualValue(user_hive, "MRU0", "10.0.0.10"))
    mstsc_key.add_value("MRU1", VirtualValue(user_hive, "MRU1", "10.0.0.11"))
    mstsc_key.add_value("MRU10", VirtualValue(user_hive, "MRU10", "10.0.0.100"))

    # Office MRU
    office_value = "[F00000000][T01D72F6E719BE870][O00000000]*C:\\path"
    excel_15_file_key = VirtualKey(user_hive, "Software\\Microsoft\\Office\\15.0\\Excel\\File MRU")
    excel_15_file_key.add_value("Item 1", VirtualValue(user_hive, "Item 1", office_value))
    excel_15_file_key.add_value("Item 2", VirtualValue(user_hive, "Item 2", office_value))
    excel_16_place_key = VirtualKey(user_hive, "Software\\Microsoft\\Office\\16.0\\Excel\\Place MRU")
    excel_16_place_key.add_value("Item 1", VirtualValue(user_hive, "Item 1", office_value))
    excel_16_place_key.add_value("Item 2", VirtualValue(user_hive, "Item 2", office_value))

    user_hash = "ADAL_6D9010B2B7A1483B256AE7477738DBA7C530BD9BA53DB1D6691441E74B83608A"
    excel_16_user_file_key = VirtualKey(
        user_hive, "Software\\Microsoft\\Office\\16.0\\Excel\\User MRU\\" + user_hash + "\\File MRU"
    )
    excel_16_user_file_key.add_value("Item 1", VirtualValue(user_hive, "Item 1", office_value))
    excel_16_user_file_key.add_value("Item 2", VirtualValue(user_hive, "Item 2", office_value))

    for key in [
        run_key,
        recentdocs_key,
        opensave_key,
        lastvisited_key,
        acmru_key,
        networkdrive_key,
        mstsc_key,
        excel_15_file_key,
        excel_16_place_key,
        excel_16_user_file_key,
    ]:
        user_hive.map_key(key.path, key)

    target_win_users.registry.map_hive(f"HKEY_USERS\\{user_details.user.sid}", user_hive)
    target_win_users.registry._hives_to_users[user_hive] = user_details
    return target_win_users


def test_mru_plugin(target_win_mru):
    run = list(target_win_mru.mru.run())
    recentdocs = list(target_win_mru.mru.recentdocs())
    opensave = list(target_win_mru.mru.opensave())
    lastvisited = list(target_win_mru.mru.lastvisited())
    acmru = list(target_win_mru.mru.acmru())
    networkdrive = list(target_win_mru.mru.networkdrive())
    mstsc = list(target_win_mru.mru.mstsc())
    msoffice = list(target_win_mru.mru.msoffice())

    assert len(run) == 2
    assert len(recentdocs) == 1
    assert len(opensave) == 4
    assert len(lastvisited) == 2
    assert len(acmru) == 2
    assert len(networkdrive) == 2
    assert len(mstsc) == 3
    assert len(msoffice) == 6

    assert len(list(target_win_mru.mru.get_all_records())) == 22
