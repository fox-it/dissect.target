from __future__ import annotations

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.regutil import RegistryHive, VirtualKey
from dissect.target.plugins.os.windows.regf.appxdebugkeys import AppxDebugKeysPlugin
from dissect.target.target import Target


def strip_hive(key_path: str) -> str:
    _, _, path = key_path.partition("\\")
    return path


PACKAGED_APPX_KEY_NAME = strip_hive(
    AppxDebugKeysPlugin.REGKEY_GLOBS[0].replace(
        "*",
        "Some.AppX.Package_1.10.3",
        1,
    )
)
PACKAGED_APPX_VALUE_NAME = "(Default)"

ACTIVATABLE_CLASSES_KEY_NAME = strip_hive(
    AppxDebugKeysPlugin.REGKEY_GLOBS[1]
    .replace(
        "*",
        "Some.AppX.Package_1.10.3",
        1,
    )
    .replace(
        "*",
        "Some.AppX.Package.Component.AppX",
        1,
    ),
)
ACTIVATABLE_CLASSES_VALUE_NAME = "DebugPath"

RANDOM_KEY_NAME = f"{ACTIVATABLE_CLASSES_KEY_NAME}\\Random"

DEBUG_INFO = "C:\\windows\\system32\\cmd.exe"


@pytest.fixture
def target_win_appx(target_win_users: Target, hive_hku: RegistryHive) -> Target:
    packaged_appx_key = VirtualKey(hive_hku, PACKAGED_APPX_KEY_NAME)
    packaged_appx_key.add_value(PACKAGED_APPX_VALUE_NAME, DEBUG_INFO)
    hive_hku.map_key(PACKAGED_APPX_KEY_NAME, packaged_appx_key)

    activatable_classes_key = VirtualKey(hive_hku, ACTIVATABLE_CLASSES_KEY_NAME)
    activatable_classes_key.add_value(ACTIVATABLE_CLASSES_VALUE_NAME, DEBUG_INFO)
    hive_hku.map_key(ACTIVATABLE_CLASSES_KEY_NAME, activatable_classes_key)

    random_key = VirtualKey(hive_hku, RANDOM_KEY_NAME)
    hive_hku.map_key(RANDOM_KEY_NAME, random_key)

    return target_win_users


def test_appx_debug_keys_plugin_walk(target_win_appx: Target, hive_hku: RegistryHive) -> Target:
    appx_plugin = AppxDebugKeysPlugin(target_win_appx)
    key = hive_hku.key(ACTIVATABLE_CLASSES_KEY_NAME)
    records = list(appx_plugin._walk(key))

    assert len(records) == 2

    assert records[0].name == ACTIVATABLE_CLASSES_VALUE_NAME
    assert records[0].debug_info == DEBUG_INFO

    # Empty keys should also be returned
    assert records[1].name is None
    assert records[1].debug_info is None


def test_appx_debug_keys__debug_keys(target_win_appx: Target) -> None:
    appx_plugin = AppxDebugKeysPlugin(target_win_appx)
    records = list(appx_plugin._debug_keys())

    assert len(records) == 3


def test_appx_debug_keys_check_compatible(target_win_appx: Target) -> None:
    appx_plugin = AppxDebugKeysPlugin(target_win_appx)
    appx_plugin.check_compatible()


def test_appx_debug_keys_check_compatible_fail() -> None:
    appx_plugin = AppxDebugKeysPlugin(Target())
    with pytest.raises(UnsupportedPluginError):
        appx_plugin.check_compatible()


def test_appx_debug_keys_appxdebugkeys(target_win_appx: Target) -> None:
    appx_plugin = AppxDebugKeysPlugin(target_win_appx)
    records = list(appx_plugin.appxdebugkeys())

    assert len(records) == 3

    assert records[0].name == PACKAGED_APPX_VALUE_NAME
    assert records[0].debug_info == DEBUG_INFO

    assert records[1].name == ACTIVATABLE_CLASSES_VALUE_NAME
    assert records[1].debug_info == DEBUG_INFO

    # Empty keys should also be returned
    assert records[2].name is None
    assert records[2].debug_info is None
