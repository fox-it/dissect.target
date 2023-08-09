import logging
from io import BytesIO

import pytest
from pytest import LogCaptureFixture

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.windows.registry import RegistryPlugin
from dissect.target.target import Target


def test_missing_hives(fs_win: VirtualFilesystem, caplog: LogCaptureFixture) -> None:
    target = Target()
    target.filesystems.add(fs_win)

    caplog.set_level(logging.DEBUG)
    target.apply()

    expected = [
        f"{target}: Could not find hive: sysvol/windows/system32/config/{hive}" for hive in RegistryPlugin.SYSTEM
    ]
    expected += [
        f"{target}: Could not find hive: sysvol/windows/system32/config/RegBack/{hive}"
        for hive in RegistryPlugin.SYSTEM
    ]

    assert [record.message for record in caplog.records if record.filename == "registry.py"] == expected


def test_missing_user_hives(fs_win: VirtualFilesystem, target_win_users: Target, caplog: LogCaptureFixture) -> None:
    fs_win.makedirs("Users/John")

    caplog.set_level(logging.DEBUG)
    target_win_users.registry.load_user_hives()

    assert [record.message for record in caplog.records if record.filename == "registry.py"] == [
        f"{target_win_users}: Could not find ntuser.dat: C:/Users/John/ntuser.dat",
        f"{target_win_users}: Could not find usrclass.dat: C:/Users/John/AppData/Local/Microsoft/Windows/usrclass.dat",
    ]


def test_empty_hives(fs_win: VirtualFilesystem, caplog: LogCaptureFixture) -> None:
    fs_win.map_file_fh("windows/system32/config/SYSTEM", BytesIO())
    fs_win.map_file_fh("boot/BCD", BytesIO())

    target = Target()
    target.filesystems.add(fs_win)

    caplog.set_level(logging.WARNING)
    target.apply()

    assert [record.message for record in caplog.records if record.filename == "registry.py"] == [
        f"{target}: Empty hive: sysvol/windows/system32/config/SYSTEM",
        f"{target}: Empty BCD hive: sysvol/boot/BCD",
    ]


def test_empty_user_hives(fs_win: VirtualFilesystem, target_win_users: Target, caplog: LogCaptureFixture) -> None:
    fs_win.map_file_fh("Users/John/ntuser.dat", BytesIO())
    fs_win.map_file_fh("Users/John/AppData/Local/Microsoft/Windows/usrclass.dat", BytesIO())

    caplog.set_level(logging.WARNING)
    target_win_users.registry.load_user_hives()

    assert [record.message for record in caplog.records if record.filename == "registry.py"] == [
        f"{target_win_users}: Empty NTUSER.DAT hive: C:/Users/John/ntuser.dat",
        f"{target_win_users}: Empty UsrClass.DAT hive: C:/Users/John/AppData/Local/Microsoft/Windows/usrclass.dat",
    ]


@pytest.mark.parametrize(
    "pattern, key_names",
    [
        (
            "\\HKLM\\SOFTWARE\\Microsoft",
            ["Microsoft"],
        ),
        (
            "\\*\\SOFTWARE\\Microsoft",
            ["Microsoft"],
        ),
        (
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*\\",
            [
                "S-1-5-18",
                "S-1-5-21-3263113198-3007035898-945866154-1002",
            ],
        ),
        (
            "\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows XP\\*",
            [],
        ),
        (
            "\\*",
            [
                "HKEY_LOCAL_MACHINE",
                "HKEY_USERS",
            ],
        ),
        (
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\*\\CurrentVersion\\ProfileList",
            ["ProfileList"],
        ),
        (
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\*\\Windows NT\\*\\ProfileList\\",
            ["ProfileList"],
        ),
    ],
)
def test_registry_plugin_glob_ext(target_win_users, pattern, key_names) -> None:
    registry_plugin = target_win_users.registry

    key_collections = registry_plugin.glob_ext(pattern)
    collection_names = []
    for key_collection in key_collections:
        collection_names.append(key_collection.name)

    assert sorted(collection_names) == sorted(key_names)
