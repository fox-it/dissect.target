import os
from functools import reduce
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import (
    PLUGINS,
    NamespacePlugin,
    OSPlugin,
    Plugin,
    environment_variable_paths,
    export,
    find_plugin_functions,
    get_external_module_paths,
    plugins,
    save_plugin_import_failure,
)
from dissect.target.target import Target


def test_save_plugin_import_failure():
    test_trace = ["test-trace"]
    test_module_name = "test-module"

    with patch("traceback.format_exception", Mock(return_value=test_trace)):
        with patch("dissect.target.plugin.PLUGINS", new_callable=dict) as MOCK_PLUGINS:
            MOCK_PLUGINS["_failed"] = []
            save_plugin_import_failure(test_module_name)

            assert len(MOCK_PLUGINS["_failed"]) == 1
            assert MOCK_PLUGINS["_failed"][0].get("module") == test_module_name
            assert MOCK_PLUGINS["_failed"][0].get("stacktrace") == test_trace


@pytest.mark.parametrize(
    "env_value, expected_output",
    [
        (None, []),
        ("", []),
        (":", [Path(""), Path("")]),
    ],
)
def test_load_environment_variable(env_value, expected_output):
    with patch.object(os, "environ", {"DISSECT_PLUGINS": env_value}):
        assert environment_variable_paths() == expected_output


def test_load_module_paths():
    assert get_external_module_paths([Path(""), Path("")]) == [Path("")]


def test_load_paths_with_env():
    with patch.object(os, "environ", {"DISSECT_PLUGINS": ":"}):
        assert get_external_module_paths([Path(""), Path("")]) == [Path("")]


@patch(
    "dissect.target.plugin.plugins",
    return_value=[
        {"module": "test.x13", "exports": ["f3"], "namespace": "Warp", "class": "x13"},
        {"module": "os", "exports": ["f3"], "namespace": None, "class": "f3"},
    ],
)
@patch(
    "dissect.target.plugin.os_plugins",
    return_value=[{"module": "os.warp._os", "exports": ["f6"], "namespace": None, "class": "warp"}],
)
@patch("dissect.target.Target", create=True)
@patch("dissect.target.plugin.load")
@pytest.mark.parametrize(
    "search, findable, assert_num_found",
    [
        ("*", True, 4),  # Found with tree search using wildcard, OS plugin also registered without ns
        ("*", False, 0),  # Unfindable plugins are not found...
        ("test.x13.*", True, 1),  # Found with tree search using wildcard, expands to test.x13.f3
        ("test.x13.*", False, 0),  # Unfindable plugins are not found...
        ("test.x13", True, 1),  # Found with tree search, same as above, because users expect +*
        ("test.*", True, 1),  # Found with tree search
        ("test.[!x]*", True, 0),  # Not Found with tree search, all in test not starting with x (no x13)
        ("test.[!y]*", True, 1),  # Found with tree search, all in test not starting with y (so x13 is ok)
        ("test.???.??", True, 1),  # Found with tree search, using question marks
        ("x13", True, 0),  # Not Found: Part of namespace but no match
        ("Warp.*", True, 0),  # Not Found: Namespace != Module so 0
        ("os.warp._os.f6", True, 1),  # Found, OS-plugins also available under verbose name
        ("f6", True, 1),  # Found with classic search
        ("f6", False, 1),  # Backward compatible: unfindable has no effect on classic search
        ("Warp.f3", True, 1),  # Found with classic style search using namespace + function
        ("Warp.f3", False, 1),  # Backward compatible: unfindable has no effect on classic search
        ("f3", True, 1),  # Found with classic style search using only function
        ("os.*", True, 2),  # Found matching os.f3, os.warp._os.f6
        ("os", True, 0),  # Exception for os, because it can be a 'special' plugin (tree match ignored)
    ],
)
def test_find_plugin_functions(plugin_loader, target, os_plugins, plugins, search, findable, assert_num_found):
    class MockPlugin(MagicMock):
        __exports__ = ["f6"]  # OS exports f6
        __findable__ = findable
        __skip__ = False

        def get_all_records():
            return []

        def f3(self):
            return "F3"

        def f6(self):
            return "F6"

    plugin_loader.return_value = MockPlugin()
    target._os = MagicMock()
    target._os.__class__.__name__ = "warp"
    found, _ = find_plugin_functions(target, search)
    assert len(found) == assert_num_found


def test_find_plugin_function_windows(target_win: Target) -> None:
    found, _ = find_plugin_functions(target_win, "services")

    assert len(found) == 1
    assert found[0].name == "services"
    assert found[0].path == "os.windows.services.services"


def test_find_plugin_function_unix(target_unix: Target) -> None:
    found, _ = find_plugin_functions(target_unix, "services")

    assert len(found) == 1
    assert found[0].name == "services"
    assert found[0].path == "os.unix.linux.services.services"


TestRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/test",
    [
        ("string", "test"),
    ],
)


class _TestNSPlugin(NamespacePlugin):
    __namespace__ = "NS"


class _TestSubPlugin1(_TestNSPlugin):
    __namespace__ = "t1"

    @export(record=TestRecord)
    def test(self):
        yield TestRecord(test="test1")


class _TestSubPlugin2(_TestNSPlugin):
    __namespace__ = "t2"

    @export(record=TestRecord)
    def test(self):
        yield TestRecord(test="test2")


def test_namespace_plugin(target_win: Target) -> None:
    assert "SUBPLUGINS" in dir(_TestNSPlugin)
    # Rename the test functions to protect them from being filtered by NS

    target_win._register_plugin_functions(_TestSubPlugin1(target_win))
    target_win._register_plugin_functions(_TestSubPlugin2(target_win))
    target_win._register_plugin_functions(_TestNSPlugin(target_win))
    assert len(list(target_win.NS.test())) == 2
    assert len(target_win.NS.SUBPLUGINS) == 2

    # Remove test plugin from list afterwards to avoid order effects
    del PLUGINS["tests"]


def test_find_plugin_function_default(target_default: Target) -> None:
    found, _ = find_plugin_functions(target_default, "services")

    assert len(found) == 2
    names = [item.name for item in found]
    assert "services" in names
    assert "services" in names
    paths = [item.path for item in found]
    assert "os.unix.linux.services.services" in paths
    assert "os.windows.services.services" in paths

    found, _ = find_plugin_functions(target_default, "mcafee.msc")
    assert found[0].path == "apps.av.mcafee.msc"


@pytest.mark.parametrize(
    "pattern",
    [
        ("version,ips,hostname"),
        ("ips,version,hostname"),
        ("hostname,ips,version"),
        ("users,osinfo"),
        ("osinfo,users"),
    ],
)
def test_find_plugin_function_order(target_win: Target, pattern: str) -> None:
    found = ",".join(reduce(lambda rs, el: rs + [el.method_name], find_plugin_functions(target_win, pattern)[0], []))
    assert found == pattern


class _TestIncompatiblePlugin(Plugin):
    def check_compatible(self):
        raise UnsupportedPluginError("My incompatible plugin error")


def test_incompatible_plugin(target_bare: Target) -> None:
    with pytest.raises(UnsupportedPluginError, match="My incompatible plugin error"):
        target_bare.add_plugin(_TestIncompatiblePlugin)


def test_plugins(target_default) -> None:
    all_plugins = list(plugins())
    default_plugin_plugins = list(plugins(target_default._os_plugin))

    assert default_plugin_plugins == all_plugins

    # The all_with_home is a sentinel function, which should be loaded for a
    # target with DefaultPlugin as OS plugin.
    sentinel_function = "all_with_home"
    has_sentinel_function = False
    for plugin in default_plugin_plugins:
        if sentinel_function in plugin.get("functions", []):
            has_sentinel_function = True
            break

    assert has_sentinel_function


@pytest.mark.parametrize(
    "method_name",
    [
        "hostname",
        "ips",
        "version",
        "os",
        "architecture",
    ],
)
def test_os_plugin_property_methods(target_bare: Target, method_name: str) -> str:
    os_plugin = OSPlugin(target_bare)
    with pytest.raises(NotImplementedError):
        getattr(os_plugin, method_name)
