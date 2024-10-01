from __future__ import annotations

from typing import Any, Iterator

import pytest

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.plugins.os.windows.registry import RegistryPlugin
from dissect.target.target import Target


def current_version_key() -> str:
    hive_name, path = WindowsPlugin.CURRENT_VERSION_KEY.split("\\", maxsplit=1)
    hive_name = RegistryPlugin.SHORTNAMES.get(hive_name, hive_name)
    key_name = "\\".join([hive_name, path])

    return key_name


CURRENT_VERSION_KEY = current_version_key()


@pytest.fixture
def version_target(target_win: Target) -> Target:
    hive = target_win.registry._root
    hive.map_key(CURRENT_VERSION_KEY, VirtualKey(hive, CURRENT_VERSION_KEY))
    return target_win


@pytest.fixture
def win_plugin(version_target: Target):
    return WindowsPlugin(version_target)


@pytest.fixture
def target_win_linux_folders(target_win: Filesystem, fs_linux_sys: Filesystem) -> Iterator[Target]:
    target_win.fs.mount("/", fs_linux_sys)
    yield target_win


def map_version_value(target: Target, name: str | None, value: Any):
    if name is not None:
        hive = target.registry._root
        hive.map_value(CURRENT_VERSION_KEY, name, VirtualValue(hive, name, value))


def assert_value(result: Any, value: Any):
    if value is None:
        assert result is value
    else:
        assert result == value


@pytest.mark.parametrize(
    "name, value",
    [
        (None, None),
        ("CurrentVersion", "Some Stringy Version"),
    ],
)
def test_windowsplugin__legacy_curre_ntversion(
    version_target: Target,
    win_plugin: WindowsPlugin,
    name: str | None,
    value: Any,
):
    map_version_value(version_target, name, value)
    result = win_plugin._legacy_current_version()

    assert_value(result, value)


@pytest.mark.parametrize(
    "name, value",
    [
        (None, None),
        ("CurrentMajorVersionNumber", 10),
    ],
)
def test_windowsplugin__major_version(
    version_target: Target,
    win_plugin: WindowsPlugin,
    name: str | None,
    value: Any,
):
    map_version_value(version_target, name, value)
    result = win_plugin._major_version()

    assert_value(result, value)


@pytest.mark.parametrize(
    "name, value",
    [
        (None, None),
        ("CurrentMinorVersionNumber", 0),
    ],
)
def test_windowsplugin__minor_version(
    version_target: Target,
    win_plugin: WindowsPlugin,
    name: str | None,
    value: Any,
):
    map_version_value(version_target, name, value)
    result = win_plugin._minor_version()

    assert_value(result, value)


@pytest.mark.parametrize(
    "keys, value",
    [
        ([], None),
        ([("CurrentVersion", "x.y")], "x.y"),
        (
            [
                ("CurrentMajorVersionNumber", 10),
                ("CurrentMinorVersionNumber", 0),
            ],
            "10.0",
        ),
        (
            [
                ("CurrentMajorVersionNumber", 10),
                ("CurrentMinorVersionNumber", 0),
                ("CurrentVersion", "x.y"),
            ],
            "10.0",
        ),
        ([("CurrentMajorVersionNumber", 10)], "10."),
        ([("CurrentMinorVersionNumber", 0)], None),
    ],
)
def test_windowsplugin__nt_version(
    version_target: Target,
    win_plugin: WindowsPlugin,
    keys: list[tuple[str, Any]],
    value: str | None,
):
    for key_name, key_value in keys:
        map_version_value(version_target, key_name, key_value)
    result = win_plugin._nt_version()

    assert_value(result, value)


@pytest.mark.parametrize(
    "keys, value",
    [
        ([], None),
        (
            [
                ("CSDVersion", 5678),
                ("CurrentBuildNumber", 1234),
                ("CurrentMajorVersionNumber", 10),
                ("CurrentMinorVersionNumber", 0),
                ("CurrentVersion", "x.y"),
                ("ProductName", "Some Product"),
                ("UBR", 9012),
            ],
            "Some Product (NT 10.0) 1234.9012 5678",
        ),
        (
            [
                ("CSDVersion", 5678),
                ("CurrentBuildNumber", 1234),
                ("CurrentVersion", "x.y"),
                ("ProductName", "Some Product"),
                ("UBR", 9012),
            ],
            "Some Product (NT x.y) 1234.9012 5678",
        ),
        (
            [
                ("CurrentBuildNumber", 1234),
                ("CurrentVersion", "x.y"),
                ("ProductName", "Some Product"),
            ],
            "Some Product (NT x.y) 1234",
        ),
        (
            [
                ("ProductName", "Some Product"),
            ],
            "Some Product (NT <Unknown CurrentVersion>) <Unknown CurrentBuildNumber>",
        ),
        (
            [
                ("CurrentVersion", "x.y"),
            ],
            "<Unknown ProductName> (NT x.y) <Unknown CurrentBuildNumber>",
        ),
        (
            [
                ("CurrentBuildNumber", 1234),
            ],
            "<Unknown ProductName> (NT <Unknown CurrentVersion>) 1234",
        ),
        (
            [
                ("UBR", 9012),
            ],
            "<Unknown ProductName> (NT <Unknown CurrentVersion>) <Unknown CurrentBuildNumber>.9012",
        ),
        (
            [
                ("CSDVersion", 5678),
            ],
            "<Unknown ProductName> (NT <Unknown CurrentVersion>) <Unknown CurrentBuildNumber> 5678",
        ),
        (
            [
                ("ProductName", "Windows 10 Pro"),
                ("CurrentMajorVersionNumber", 10),
                ("CurrentMinorVersionNumber", 0),
                ("CurrentBuildNumber", 19_045),
                ("UBR", 1234),
            ],
            "Windows 10 Pro (NT 10.0) 19045.1234",
        ),
        (
            [
                ("ProductName", "Windows 10 Enterprise"),
                ("CurrentMajorVersionNumber", 10),
                ("CurrentMinorVersionNumber", 0),
                ("CurrentBuildNumber", 22_000),
                ("UBR", 1234),
            ],
            "Windows 11 Enterprise (NT 10.0) 22000.1234",
        ),
    ],
)
def test_windowsplugin_version(
    version_target: Target,
    win_plugin: WindowsPlugin,
    keys: list[tuple[str, Any]],
    value: str | None,
):
    for key_name, key_value in keys:
        map_version_value(version_target, key_name, key_value)
    result = win_plugin.version

    assert_value(result, value)


def test_windows_os_detection_with_linux_folders(target_win_linux_folders: Target) -> None:
    fs_linux = LinuxPlugin.detect(target_win_linux_folders)
    fs_windows = WindowsPlugin.detect(target_win_linux_folders)

    assert fs_linux is None
    assert fs_windows is not None
