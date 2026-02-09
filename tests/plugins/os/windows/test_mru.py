from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.target import Target

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.fixture
def target_win_mru(target_win_users: Target) -> Target:
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
    recentdocs_key.add_value("MRUListEx", VirtualValue(user_hive, "MRUListEx", b"\x00\x00\x00\x00\xff\xff\xff\xff"))
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

    # OpenSavePidlMRU
    opensave_pidl_key = VirtualKey(
        user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"
    )
    opensave_pidl_subkey = VirtualKey(user_hive, opensave_pidl_key.path + "\\*")
    opensave_pidl_subkey.add_value(
        "MRUListEx",
        VirtualValue(
            user_hive,
            "MRUListEx",
            b"\x08\x00\x00\x00\t\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00\x12\x00\x00\x00\x11\x00\x00\x00\x10\x00\x00\x00\x0f\x00\x00\x00\x0e\x00\x00\x00\r\x00\x00\x00\x0c\x00\x00\x00\x0b\x00\x00\x00\n\x00\x00\x00\xff\xff\xff\xff",
        ),
    )
    opensave_pidl_subkey.add_value(
        "0",
        VirtualValue(
            user_hive,
            "0",
            b"\x14\x00\x1fP\xe0O\xd0 \xea:i\x10\xa2\xd8\x08\x00+00\x9d\x19\x00/Z:\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00p\x002\x00\xef\x1d\x01\x00dR|j \x00W9R717~O.ZIP\x00\x00T\x00\t\x00\x04\x00\xef\xbedR|jdR|j.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00W\x00e\x00b\x00 \x00O\x00p\x00t\x00i\x00m\x00i\x00z\x00e\x00r\x00.\x00z\x00i\x00p\x00\x00\x00\x1c\x00\x00\x00",  # noqa: E501
        ),
    )
    opensave_pidl_key.add_subkey("*", opensave_pidl_subkey)

    # LastVisitedMRU
    lastvisited_key = VirtualKey(
        user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU"
    )
    lastvisited_key.add_value("MRUList", VirtualValue(user_hive, "MRUList", "ba"))
    value_a = b"\x00\x00".join([x.encode("utf-16-le") for x in ["test_a.exe", "c:\\path\\to\\something\\a", ""]])
    value_b = b"\x00\x00".join([x.encode("utf-16-le") for x in ["test_b.exe", "c:\\path\\to\\something\\b", ""]])
    lastvisited_key.add_value("a", VirtualValue(user_hive, "a", value_a))
    lastvisited_key.add_value("b", VirtualValue(user_hive, "b", value_b))

    # LastVisitedPidlMRU
    lastvisited_pidl_key = VirtualKey(
        user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU"
    )
    lastvisited_pidl_key.add_value(
        "MRUListEx",
        VirtualValue(
            user_hive,
            "MRUListEx",
            b"\x05\x00\x00\x00\x07\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff\xff\xff",
        ),
    )
    lastvisited_pidl_key.add_value(
        "1",
        VirtualValue(
            user_hive,
            "1",
            b"K\x00e\x00e\x00P\x00a\x00s\x00s\x00.\x00e\x00x\x00e\x00\x00\x00\x14\x00\x1fP\xe0O\xd0 \xea:i\x10\xa2\xd8\x08\x00+00\x9d\x14\x00.\x80\x92+\x16\xd3e\x93zF\x95k\x92p:\xca\x08\xaf\x00\x00",  # noqa: E501
        ),
    )

    # ACMru
    acmru_key = VirtualKey(user_hive, "Software\\Microsoft\\Search Assistant\\ACMru\\5603")
    acmru_key.add_value("000", VirtualValue(user_hive, "000", "value"))
    acmru_key.add_value("001", VirtualValue(user_hive, "001", "value"))
    # ACMru wordwheel query
    wordwheel_key = VirtualKey(user_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery")
    wordwheel_key.add_value("MRUListEx", VirtualValue(user_hive, "MRUListEx", b"\x00\x00\x00\x00\xff\xff\xff\xff"))
    wordwheel_key.add_value("0", VirtualValue(user_hive, "0", b"h\x00e\x00l\x00l\x00o\x00\x00\x00"))

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
        opensave_pidl_key,
        lastvisited_key,
        lastvisited_pidl_key,
        acmru_key,
        wordwheel_key,
        networkdrive_key,
        mstsc_key,
        excel_15_file_key,
        excel_16_place_key,
        excel_16_user_file_key,
    ]:
        user_hive.map_key(key.path, key)

    target_win_users.registry.add_hive(
        "HKEY_USERS",
        f"HKEY_USERS\\{user_details.user.sid}",
        user_hive,
        user_hive.filepath,
    )
    target_win_users.registry._hives_to_users[user_hive] = user_details
    return target_win_users


def test_mru_plugin(target_win_mru: Target) -> None:
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
    assert len(opensave) == 5
    # test if opensave_pidl_key is correctly resolved
    assert opensave[4].value == "My Computer\\Z:\\Web Optimizer.zip"
    assert len(lastvisited) == 3
    # test if lastvisited_pidl_key is correctly resolved
    assert lastvisited[2].filename == "KeePass.exe"
    assert lastvisited[2].path == "My Computer\\{d3162b92-9365-467a-956b-92703aca08af}\\"
    assert len(acmru) == 3
    assert len(networkdrive) == 2
    assert len(mstsc) == 3
    assert len(msoffice) == 6

    assert len(list(target_win_mru.mru())) == 25
