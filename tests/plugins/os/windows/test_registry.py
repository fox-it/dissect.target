from __future__ import annotations

import logging
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.windows.registry import RegistryPlugin
from dissect.target.target import Target

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem


def test_missing_hives(fs_win: VirtualFilesystem, caplog: pytest.LogCaptureFixture) -> None:
    target = Target()
    target.filesystems.add(fs_win)

    with caplog.at_level(logging.DEBUG, target.log.name):
        target.apply()

        expected = []

        base_paths = [
            "sysvol/windows/system32/config",
            "sysvol/WINNT/system32/config",
            "sysvol/windows",
            "sysvol/reactos",
            "sysvol/windows/system32/config/RegBack",
        ]

        for base_path in base_paths:
            expected += [f"{target}: Could not find hive: {base_path}/{hive}" for hive in RegistryPlugin.SYSTEM]

        assert [record.message for record in caplog.records if record.filename == "registry.py"] == expected


def test_missing_user_hives(
    fs_win: VirtualFilesystem, target_win_users: Target, caplog: pytest.LogCaptureFixture
) -> None:
    fs_win.makedirs("Users/John")

    with caplog.at_level(logging.DEBUG, target_win_users.log.name):
        target_win_users.registry.load_user_hives()

        assert [record.message for record in caplog.records if record.filename == "registry.py"] == [
            f"{target_win_users}: Could not find ntuser.dat: C:/Users/John/ntuser.dat",
            f"{target_win_users}: Could not find usrclass.dat: C:/Users/John/AppData/Local/Microsoft/Windows/usrclass.dat",  # noqa: E501
        ]


def test_empty_hives(fs_win: VirtualFilesystem, caplog: pytest.LogCaptureFixture) -> None:
    fs_win.map_file_fh("windows/system32/config/SYSTEM", BytesIO())
    fs_win.map_file_fh("boot/BCD", BytesIO())

    target = Target()
    target.filesystems.add(fs_win)

    with caplog.at_level(logging.WARNING, target.log.name):
        target.apply()

        assert [record.message for record in caplog.records if record.filename == "registry.py"] == [
            f"{target}: Empty hive: sysvol/windows/system32/config/SYSTEM",
            f"{target}: Empty BCD hive: sysvol/boot/BCD",
        ]


def test_empty_hives_skip_warning(fs_win: VirtualFilesystem, caplog: pytest.LogCaptureFixture) -> None:
    fake_fh = BytesIO()
    fake_fh.size = 1
    fs_win.map_file_fh("windows/system32/config/SYSTEM", fake_fh)
    fs_win.map_file_fh("windows/system32/config/RegBack/SYSTEM", BytesIO())

    target = Target()
    target.filesystems.add(fs_win)

    with (
        caplog.at_level(logging.WARNING, target.log.name),
        patch("dissect.target.plugins.os.windows.registry.RegfHive"),
    ):
        target.apply()

        assert [record.message for record in caplog.records if record.filename == "registry.py"] == []


def test_empty_user_hives(
    fs_win: VirtualFilesystem, target_win_users: Target, caplog: pytest.LogCaptureFixture
) -> None:
    fs_win.map_file_fh("Users/John/ntuser.dat", BytesIO())
    fs_win.map_file_fh("Users/John/AppData/Local/Microsoft/Windows/usrclass.dat", BytesIO())

    with caplog.at_level(logging.WARNING, target_win_users.log.name):
        target_win_users.registry.load_user_hives()

        assert [record.message for record in caplog.records if record.filename == "registry.py"] == [
            f"{target_win_users}: Empty NTUSER.DAT hive: C:/Users/John/ntuser.dat",
            f"{target_win_users}: Empty UsrClass.DAT hive: C:/Users/John/AppData/Local/Microsoft/Windows/usrclass.dat",
        ]


@pytest.mark.parametrize(
    ("pattern", "key_names"),
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
def test_registry_plugin_glob_ext(target_win_users: Target, pattern: str, key_names: list[str]) -> None:
    registry_plugin = target_win_users.registry

    key_collections = registry_plugin.glob_ext(pattern)
    collection_names = [key_collection.name for key_collection in key_collections]

    assert sorted(collection_names) == sorted(key_names)


def test_registry_plugin_root_none(target_win_users: Target) -> None:
    plugin: RegistryPlugin = target_win_users.registry

    assert plugin.key()
    assert plugin.key("")
