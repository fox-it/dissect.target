from __future__ import annotations

import logging
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.os.windows.registry import RegistryPlugin
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterable

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


@pytest.mark.parametrize(
    ("keys", "values", "expected_output"),
    [
        pytest.param(
            "HKLM\\SOFTWARE\\SomePath",
            "Foo",
            ["FooValue"],
            id="single-key-single-value",
        ),
        pytest.param(
            "HKLM\\SOFTWARE\\SomePath",
            ("Foo", "Bar"),
            ["FooValue", "BarValue"],
            id="single-key-multi-value",
        ),
        pytest.param(
            ("HKLM\\SOFTWARE\\SomePath", "HKLM\\SOFTWARE\\AnotherPath"),
            "Foo",
            ["FooValue", "AnotherFooValue"],
            id="multi-key-single-value",
        ),
        pytest.param(
            ("HKLM\\SOFTWARE\\SomePath", "HKLM\\SOFTWARE\\AnotherPath"),
            ("Foo", "Bar"),
            ["FooValue", "BarValue", "AnotherFooValue", "AnotherBarValue"],
            id="multi-key-multi-value",
        ),
    ],
)
def test_registry_plugin_values_keys(
    target_win_users: Target,
    hive_hklm: VirtualHive,
    keys: str | Iterable[str] | None,
    values: str | Iterable[str] | None,
    expected_output: list[str],
) -> None:
    """Test if we can handle different input values for :meth:`RegistryPlugin.values`."""

    key_path = "SOFTWARE\\SomePath"
    key = VirtualKey(hive_hklm, key_path)
    key.add_value("Foo", VirtualValue(hive_hklm, "Foo", "FooValue"))
    key.add_value("Bar", VirtualValue(hive_hklm, "Bar", "BarValue"))
    hive_hklm.map_key(key_path, key)

    key_path = "SOFTWARE\\AnotherPath"
    key = VirtualKey(hive_hklm, key_path)
    key.add_value("Foo", VirtualValue(hive_hklm, "Foo", "AnotherFooValue"))
    key.add_value("Bar", VirtualValue(hive_hklm, "Bar", "AnotherBarValue"))
    hive_hklm.map_key(key_path, key)

    assert [v.value for v in target_win_users.registry.values(keys, values)] == expected_output


def test_registry_plugin_keys_ignore_regback(
    target_win_users: Target,
    hive_hklm: VirtualHive,
    fs_win: VirtualFilesystem,
) -> None:
    """Test that the ignore_regback functionality works correctly."""
    from pathlib import Path
    from unittest.mock import Mock

    # Set up the registry plugin on the target
    target_win_users.registry._hive_collections["SOFTWARE"].add(hive_hklm)
    target_win_users.registry._map_hive("HKEY_LOCAL_MACHINE\\SOFTWARE", hive_hklm)

    # Create a normal registry key
    key_path = "SOFTWARE\\TestKey"
    normal_key = VirtualKey(hive_hklm, key_path)
    normal_key.add_value("TestValue", VirtualValue(hive_hklm, "TestValue", "NormalValue"))
    hive_hklm.map_key(key_path, normal_key)

    # Test without ignore_regback parameter (should use default from target.props)
    target_win_users.props["ignore_regback"] = False
    normal_keys = list(target_win_users.registry.keys("HKEY_LOCAL_MACHINE\\SOFTWARE\\TestKey"))
    assert len(normal_keys) == 1  # Only the normal key

    # Test with ignore_regback=True explicitly
    filtered_keys = list(target_win_users.registry.keys("HKEY_LOCAL_MACHINE\\SOFTWARE\\TestKey", ignore_regback=True))
    assert len(filtered_keys) == 1  # Still 1 since we only have the normal key

    # Test that target.props.ignore_regback is respected when parameter is not provided
    target_win_users.props["ignore_regback"] = True
    default_keys = list(target_win_users.registry.keys("HKEY_LOCAL_MACHINE\\SOFTWARE\\TestKey"))
    assert len(default_keys) == 1

    # Test the _is_regback_key method directly
    assert not target_win_users.registry._is_regback_key(normal_keys[0])

    # Test with a mock RegBack key
    regback_hive = Mock()
    regback_hive.filepath = Path("sysvol/windows/system32/config/RegBack/SOFTWARE")

    regback_key = Mock()
    regback_key.hive = regback_hive
    regback_key.name = "TestKey"

    assert target_win_users.registry._is_regback_key(regback_key)
