import os
import textwrap
from functools import reduce
from pathlib import Path
from typing import Iterator, Optional
from unittest.mock import MagicMock, Mock, patch

import pytest
from flow.record import Record

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import EmptyRecord, create_extended_descriptor
from dissect.target.plugin import (
    FunctionDescriptor,
    NamespacePlugin,
    OSPlugin,
    Plugin,
    PluginDescriptor,
    _generate_long_paths,
    _save_plugin_import_failure,
    environment_variable_paths,
    export,
    find_plugin_functions,
    get_external_module_paths,
    load_modules_from_paths,
    plugins,
)
from dissect.target.target import Target


@pytest.fixture(autouse=True)
def clear_caches() -> Iterator[None]:
    _generate_long_paths.cache_clear()
    yield
    _generate_long_paths.cache_clear()


def test_save_plugin_import_failure() -> None:
    test_trace = ["test-trace"]
    test_module_name = "test-module"

    with patch("traceback.format_exception", Mock(return_value=test_trace)):
        with patch("dissect.target.plugin.PLUGINS", new_callable=dict) as mock_plugins:
            mock_plugins["__failed__"] = []
            _save_plugin_import_failure(test_module_name)

            assert len(mock_plugins["__failed__"]) == 1
            assert mock_plugins["__failed__"][0].module == test_module_name
            assert mock_plugins["__failed__"][0].stacktrace == test_trace


@pytest.mark.parametrize(
    "env_value, expected_output",
    [
        (None, []),
        ("", []),
        (":", [Path(""), Path("")]),
    ],
)
def test_load_environment_variable(env_value: Optional[str], expected_output: list[Path]) -> None:
    with patch.object(os, "environ", {"DISSECT_PLUGINS": env_value}):
        assert environment_variable_paths() == expected_output


def test_load_module_paths() -> None:
    assert get_external_module_paths([Path(""), Path("")]) == [Path("")]


def test_load_paths_with_env() -> None:
    with patch.object(os, "environ", {"DISSECT_PLUGINS": ":"}):
        assert get_external_module_paths([Path(""), Path("")]) == [Path("")]


class MockOSWarpPlugin(OSPlugin):
    __exports__ = ["f6"]  # OS exports f6
    __register__ = False
    __name__ = "warp"

    def __init__(self):
        pass

    def f3(self) -> str:
        return "F3"

    def f6(self) -> str:
        return "F6"


@patch(
    "dissect.target.plugin._get_plugins",
    return_value={
        "__functions__": {
            None: {
                "Warp.f3": {
                    "test.x13.x13": FunctionDescriptor(
                        name="Warp.f3",
                        namespace="Warp",
                        path="test.x13.f3",
                        exported=True,
                        internal=False,
                        findable=True,
                        output="record",
                        method_name="f3",
                        module="test.x13",
                        qualname="x13",
                    )
                },
                "f3": {
                    "os.f3": FunctionDescriptor(
                        name="f3",
                        namespace=None,
                        path="os.f3",
                        exported=True,
                        internal=False,
                        findable=True,
                        output="record",
                        method_name="f3",
                        module="os",
                        qualname="f3",
                    )
                },
                "f22": {
                    "test.x69.x69": FunctionDescriptor(
                        name="f22",
                        namespace=None,
                        path="test.x69.f22",
                        exported=True,
                        internal=False,
                        findable=False,
                        output="record",
                        method_name="f22",
                        module="test.x69",
                        qualname="x69",
                    )
                },
            },
            "__os__": {
                "f6": {
                    "os.warp._os.warp": FunctionDescriptor(
                        name="f6",
                        namespace=None,
                        path="os.warp._os.f6",
                        exported=True,
                        internal=False,
                        findable=True,
                        output="record",
                        method_name="f6",
                        module="os.warp._os",
                        qualname="warp",
                    )
                }
            },
        },
        "__ostree__": {"os": {"warp": {}}},
    },
)
@patch("dissect.target.Target", create=True)
@pytest.mark.parametrize(
    "search, assert_num_found",
    [
        ("*", 2),  # Found with tree search using wildcard, excluding OS plugins and unfindable
        ("test.x13.*", 1),  # Found with tree search using wildcard, expands to test.x13.f3
        ("test.x13", 1),  # Found with tree search, same as above, because users expect +*
        ("test.x13.f3", 1),
        ("test.*", 1),  # Found with tree search
        ("test.[!x]*", 0),  # Not Found with tree search, all in test not starting with x (no x13)
        ("test.[!y]*", 1),  # Found with tree search, all in test not starting with y (so x13 is ok)
        ("test.???.??", 1),  # Found with tree search, using question marks
        ("x13", 0),  # Not Found: Part of namespace but no match
        ("Warp.*", 0),  # Not Found: Namespace != Module so 0
        ("os.warp._os.f6", 0),  # OS plugins are excluded from tree search
        ("f6", 1),  # Found with direct match
        ("f22", 1),  # Unfindable has no effect on direct match
        ("Warp.f3", 1),  # Found with namespace + function
        ("f3", 1),  # Found direct match
        ("os.*", 1),  # Found matching os.f3
        ("os", 1),  # No tree search for "os" because it's a direct match
    ],
)
def test_find_plugin_functions(target: MagicMock, plugins: dict, search: str, assert_num_found: int) -> None:
    target._os_plugin = MockOSWarpPlugin
    target._os_plugin.__module__ = "dissect.target.plugins.os.warp._os"

    found, _ = find_plugin_functions(search, target)
    assert len(found) == assert_num_found


def test_find_plugin_function_windows(target_win: Target) -> None:
    found, _ = find_plugin_functions("services", target_win)

    assert len(found) == 1
    assert found[0].name == "services"
    assert found[0].path == "os.windows.services.services"


def test_find_plugin_function_linux(target_linux: Target) -> None:
    found, _ = find_plugin_functions("services", target_linux)

    assert len(found) == 1
    assert found[0].name == "services"
    assert found[0].path == "os.unix.linux.services.services"


TestRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/test",
    [
        ("string", "value"),
    ],
)


class _TestNSPlugin(NamespacePlugin):
    __namespace__ = "NS"
    __register__ = False

    @export(record=TestRecord)
    def test_all(self):
        # Iterate all functions of all subclasses
        yield from self.test()


class _TestSubPlugin1(_TestNSPlugin):
    __namespace__ = "t1"
    __register__ = False

    @export(record=TestRecord)
    def test(self):
        yield TestRecord(value="test1")


class _TestSubPlugin2(_TestNSPlugin):
    __namespace__ = "t2"
    __register__ = False

    @export(record=TestRecord)
    def test(self):
        yield TestRecord(value="test2")


class _TestSubPlugin3(_TestSubPlugin2):
    __namespace__ = "t3"
    __register__ = False

    # Override the test() function of t2
    @export(record=TestRecord)
    def test(self):
        yield TestRecord(value=self._value())

    def _value(self):
        return "test3"


class _TestSubPlugin4(_TestSubPlugin3):
    __namespace__ = "t4"
    __register__ = False

    # Do not override the test() function of t3, but change the _value function instead.
    def _value(self):
        return "test4"

    @export(record=TestRecord)
    def test_all(self):
        yield TestRecord(value="overridden")


def test_namespace_plugin(target_win: Target) -> None:
    assert "SUBPLUGINS" in dir(_TestNSPlugin)
    # Rename the test functions to protect them from being filtered by NS

    target_win._register_plugin_functions(_TestSubPlugin1(target_win))
    target_win._register_plugin_functions(_TestSubPlugin2(target_win))
    target_win._register_plugin_functions(_TestSubPlugin3(target_win))
    target_win._register_plugin_functions(_TestSubPlugin4(target_win))
    target_win._register_plugin_functions(_TestNSPlugin(target_win))
    assert len(list(target_win.NS.test())) == 4
    assert len(target_win.NS.SUBPLUGINS) == 4

    assert sorted([item.value for item in target_win.NS.test()]) == ["test1", "test2", "test3", "test4"]
    assert sorted([item.value for item in target_win.t1.test()]) == ["test1"]
    assert sorted([item.value for item in target_win.t2.test()]) == ["test2"]
    assert sorted([item.value for item in target_win.t3.test()]) == ["test3"]
    assert sorted([item.value for item in target_win.t4.test()]) == ["test4"]

    # Check whether we can access all subclass functions from the superclass
    assert sorted([item.value for item in target_win.NS.test_all()]) == ["test1", "test2", "test3", "test4"]

    # Check whether we can access the overridden function when explicitly accessing the subplugin
    assert next(target_win.t4.test_all()).value == "overridden"


def test_find_plugin_function_default(target_default: Target) -> None:
    found, _ = find_plugin_functions("services", target_default)

    assert len(found) == 2
    names = [item.name for item in found]
    assert "services" in names
    assert "services" in names
    paths = [item.path for item in found]
    assert "os.unix.linux.services.services" in paths
    assert "os.windows.services.services" in paths

    found, _ = find_plugin_functions("mcafee.msc", target_default)
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
    found = ",".join(reduce(lambda rs, el: rs + [el.method_name], find_plugin_functions(pattern, target_win)[0], []))
    assert found == pattern


class _TestIncompatiblePlugin(Plugin):
    def check_compatible(self):
        raise UnsupportedPluginError("My incompatible plugin error")


def test_incompatible_plugin(target_bare: Target) -> None:
    with pytest.raises(UnsupportedPluginError, match="My incompatible plugin error"):
        target_bare.add_plugin(_TestIncompatiblePlugin)


MOCK_PLUGINS_OLD = {
    "apps": {  # Plugin descriptors in this branch should be returned for any osfilter
        "mail": {"module": "apps.mail", "functions": "mail"},
    },
    "os": {
        # The OSPlugin for Generic OS, plugins in this branch should only be
        # returned when the osfilter starts with "os." or is None.
        # The _os plugin itself should only be returned if special_keys
        # contains the "_os" key.
        "_os": {"module": "os._os", "functions": "GenericOS"},
        "apps": {
            "app1": {"module": "os.apps.app1", "functions": "app1"},
            "app2": {"module": "os.apps.app2", "functions": "app2"},
        },
        "fooos": {
            # The OSPlugin for FooOS, plugins in this branch should only be
            # returned when the osfilter is "os.fooos" or "os.fooos._os" or
            # None.
            "_os": {"module": "os.foos._os", "functions": "FooOS"},
            "foobar": {"module": "os.foos.foobar", "functions": "foobar"},
            # The plugins under _misc should only be returned if special_keys
            # contains the "_misc" key.
            "_misc": {
                "bar": {"module": "os.foos._misc.bar", "functions": "bar"},
                "tender": {"module": "os.foos._misc.tender", "functions": "tender"},
            },
            "apps": {
                "foo_app": {"module": "os.foos.apps.foo_app", "functions": "foo_app"},
                "bar_app": {"module": "os.foos.apps.bar_app", "functions": "bar_app"},
            },
        },
    },
}

MOCK_PLUGINS = {
    "__functions__": {
        None: {
            "mail": {
                "apps.mail.MailPlugin": FunctionDescriptor(
                    name="mail",
                    namespace=None,
                    path="apps.mail.mail",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="mail",
                    module="apps.mail",
                    qualname="MailPlugin",
                )
            },
            "app1": {
                "os.apps.app1.App1Plugin": FunctionDescriptor(
                    name="app1",
                    namespace=None,
                    path="os.apps.app1.app1",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="app1",
                    module="os.apps.app1",
                    qualname="App1Plugin",
                )
            },
            "app2": {
                "os.apps.app2.App2Plugin": FunctionDescriptor(
                    name="app2",
                    namespace=None,
                    path="os.apps.app2.app2",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="app2",
                    module="os.apps.app2",
                    qualname="App2Plugin",
                ),
                "os.fooos.apps.app2.App2Plugin": FunctionDescriptor(
                    name="app2",
                    namespace=None,
                    path="os.fooos.apps.app2.app2",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="app2",
                    module="os.fooos.apps.app2",
                    qualname="App2Plugin",
                ),
            },
            "foo_app": {
                "os.fooos.apps.foo_app.FooAppPlugin": FunctionDescriptor(
                    name="foo_app",
                    namespace=None,
                    path="os.fooos.apps.foo_app.foo_app",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="foo_app",
                    module="os.foos.apps.foo_app",
                    qualname="FooAppPlugin",
                )
            },
            "bar_app": {
                "os.fooos.apps.bar_app.BarAppPlugin": FunctionDescriptor(
                    name="bar_app",
                    namespace=None,
                    path="os.fooos.apps.bar_app.bar_app",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="bar_app",
                    module="os.foos.apps.bar_app",
                    qualname="BarAppPlugin",
                )
            },
            "foobar": {
                "os.fooos.foobar.FooBarPlugin": FunctionDescriptor(
                    name="foobar",
                    namespace=None,
                    path="os.fooos.foobar.foobar",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="foobar",
                    module="os.foos.foobar",
                    qualname="FooBarPlugin",
                )
            },
        },
        "__os__": {
            "generic_os": {
                "os._os.GenericOS": FunctionDescriptor(
                    name="generic_os",
                    namespace=None,
                    path="os._os.generic_os",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="generic_os",
                    module="os._os",
                    qualname="GenericOS",
                )
            },
            "foo_os": {
                "os.fooos._os.FooOS": FunctionDescriptor(
                    name="foo_os",
                    namespace=None,
                    path="os.fooos._os.foo_os",
                    exported=True,
                    internal=False,
                    findable=True,
                    output="record",
                    method_name="foo_os",
                    module="os.fooos._os",
                    qualname="FooOS",
                )
            },
        },
    },
    "__plugins__": {
        None: {
            "apps.mail.MailPlugin": PluginDescriptor(
                module="apps.mail",
                qualname="MailPlugin",
                namespace=None,
                path="apps.mail",
                findable=True,
                functions=["mail"],
                exports=["mail"],
            ),
            "os.apps.app1.App1Plugin": PluginDescriptor(
                module="os.apps.app1",
                qualname="App1Plugin",
                namespace=None,
                path="os.apps.app1",
                findable=True,
                functions=["app1"],
                exports=["app1"],
            ),
            "os.apps.app2.App2Plugin": PluginDescriptor(
                module="os.apps.app2",
                qualname="App2Plugin",
                namespace=None,
                path="os.apps.app2",
                findable=True,
                functions=["app2"],
                exports=["app2"],
            ),
            "os.fooos.apps.app2.App2Plugin": PluginDescriptor(
                module="os.fooos.apps.app2",
                qualname="App2Plugin",
                namespace=None,
                path="os.fooos.apps.app2",
                findable=True,
                functions=["app2"],
                exports=["app2"],
            ),
            "os.fooos.apps.foo_app.FooAppPlugin": PluginDescriptor(
                module="os.fooos.apps.foo_app",
                qualname="FooAppPlugin",
                namespace=None,
                path="os.fooos.apps.foo_app",
                findable=True,
                functions=["foo_app"],
                exports=["foo_app"],
            ),
            "os.fooos.apps.bar_app.BarAppPlugin": PluginDescriptor(
                module="os.fooos.apps.bar_app",
                qualname="BarAppPlugin",
                namespace=None,
                path="os.fooos.apps.bar_app",
                findable=True,
                functions=["bar_app"],
                exports=["bar_app"],
            ),
            "os.fooos.foobar.FooBarPlugin": PluginDescriptor(
                module="os.fooos.foobar",
                qualname="FooBarPlugin",
                namespace=None,
                path="os.fooos.foobar",
                findable=True,
                functions=["foobar"],
                exports=["foobar"],
            ),
        },
        "__os__": {
            "os._os.GenericOS": PluginDescriptor(
                module="os._os",
                qualname="GenericOS",
                namespace=None,
                path="os._os",
                findable=True,
                functions=["generic_os"],
                exports=["generic_os"],
            ),
            "os.fooos._os.FooOS": PluginDescriptor(
                module="os.fooos._os",
                qualname="FooOS",
                namespace=None,
                path="os.fooos._os",
                findable=True,
                functions=["foo_os"],
                exports=["foo_os"],
            ),
        },
    },
    "__ostree__": {
        "os": {
            "fooos": {},
        }
    },
}


@pytest.mark.parametrize(
    "osfilter, index, expected_plugins",
    [
        (
            None,
            None,
            [
                "apps.mail",
                "os.apps.app1",
                "os.apps.app2",
                "os.fooos.apps.app2",
                "os.fooos.apps.bar_app",
                "os.fooos.apps.foo_app",
                "os.fooos.foobar",
            ],
        ),
        (
            None,
            "__os__",
            [
                "os._os",
                "os.fooos._os",
            ],
        ),
        (
            "os._os",
            None,
            [
                "apps.mail",
                "os.apps.app1",
                "os.apps.app2",
            ],
        ),
        (
            "os.fooos._os",
            None,
            [
                "apps.mail",
                "os.apps.app1",
                "os.apps.app2",
                "os.fooos.apps.app2",
                "os.fooos.apps.bar_app",
                "os.fooos.apps.foo_app",
                "os.fooos.foobar",
            ],
        ),
        (
            "bar",
            None,
            ["apps.mail"],
        ),
    ],
)
def test_plugins(
    osfilter: str,
    index: str,
    expected_plugins: list[str],
) -> None:
    with (
        patch("dissect.target.plugin._get_plugins", return_value=MOCK_PLUGINS),
        patch("dissect.target.plugin._module_path", return_value=osfilter),
    ):
        if osfilter is not None:
            # osfilter must be a class or None
            osfilter = Mock

        plugin_descriptors = plugins(osfilter=osfilter, index=index)

        assert sorted([desc.module for desc in plugin_descriptors]) == sorted(expected_plugins)


def test_plugins_default_plugin(target_default: Target) -> None:
    all_plugins = list(plugins())
    default_plugin_plugins = list(plugins(osfilter=target_default._os_plugin))

    assert default_plugin_plugins == all_plugins

    # The all_with_home is a sentinel function, which should be loaded for a
    # target with DefaultPlugin as OS plugin.
    sentinel_function = "all_with_home"
    has_sentinel_function = False
    for plugin in default_plugin_plugins:
        if sentinel_function in plugin.functions:
            has_sentinel_function = True
            break

    assert has_sentinel_function

    default_os_plugin_desc = plugins(osfilter=target_default._os_plugin, index="__os__")

    assert len(list(default_os_plugin_desc)) == 1


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
def test_os_plugin_property_methods(target_bare: Target, method_name: str) -> None:
    os_plugin = OSPlugin(target_bare)
    with pytest.raises(NotImplementedError):
        getattr(os_plugin, method_name)


class MockOS1(OSPlugin):
    __register__ = False

    @export(property=True)
    def hostname(self) -> Optional[str]:
        pass

    @export(property=True)
    def ips(self) -> list[str]:
        pass

    @export(property=True)
    def version(self) -> Optional[str]:
        pass

    @export(record=EmptyRecord)
    def users(self) -> list[Record]:
        pass

    @export(property=True)
    def os(self) -> str:
        pass

    @export(property=True)
    def architecture(self) -> Optional[str]:
        pass


class MockOS2(OSPlugin):
    __register__ = False

    @export(property=True)
    def hostname(self) -> Optional[str]:
        """Test docstring hostname"""
        pass

    @export(property=True)
    def ips(self) -> list[str]:
        """Test docstring ips"""
        pass

    @export(property=True)
    def version(self) -> Optional[str]:
        """Test docstring version"""
        pass

    @export(record=EmptyRecord)
    def users(self) -> list[Record]:
        """Test docstring users"""
        pass

    @export(property=True)
    def os(self) -> str:
        """Test docstring os"""
        pass

    @export(property=True)
    def architecture(self) -> Optional[str]:
        """Test docstring architecture"""
        pass


@pytest.mark.parametrize(
    "subclass, replaced",
    [
        (MockOS1, True),
        (MockOS2, False),
    ],
)
def test_os_plugin___init_subclass__(subclass: type[OSPlugin], replaced: bool) -> None:
    exported_methods = {
        "hostname",
        "ips",
        "version",
        "users",
        "os",
        "architecture",
    }

    for method_name in exported_methods:
        os_method = getattr(OSPlugin, method_name)
        if isinstance(os_method, property):
            os_method = os_method.fget
        os_docstring = os_method.__doc__

        subclass_method = getattr(subclass, method_name)
        if isinstance(subclass_method, property):
            subclass_method = subclass_method.fget
        subclass_docstring = subclass_method.__doc__

        assert (os_docstring == subclass_docstring) is replaced
        if not replaced:
            assert subclass_docstring == f"Test docstring {method_name}"


@patch("dissect.target.plugin.PLUGINS", new_callable=dict)
def test_plugin_directory(mock_plugins: dict, tmp_path: Path) -> None:
    code = """
        from dissect.target.plugin import Plugin, export

        class MyPlugin(Plugin):
            __namespace__ = {!r}

            @export
            def my_function(self):
                return "My function"
    """

    (tmp_path / "myplugin").mkdir()
    (tmp_path / "myplugin" / "__init__.py").write_text("")
    (tmp_path / "myplugin" / "_plugin.py").write_text(textwrap.dedent(code.format(None)))

    (tmp_path / "mypluginns").mkdir()
    (tmp_path / "mypluginns" / "__init__.py").write_text("")
    (tmp_path / "mypluginns" / "_plugin.py").write_text(textwrap.dedent(code.format("myns")))

    load_modules_from_paths([tmp_path])

    assert mock_plugins["__functions__"][None] == {
        "my_function": {
            "myplugin.MyPlugin": FunctionDescriptor(
                name="my_function",
                namespace=None,
                path="myplugin.my_function",
                exported=True,
                internal=False,
                findable=True,
                output="default",
                method_name="my_function",
                module="myplugin._plugin",
                qualname="MyPlugin",
            )
        },
        "myns": {
            "mypluginns.MyPlugin": FunctionDescriptor(
                name="myns",
                namespace="myns",
                path="mypluginns",
                exported=True,
                internal=False,
                findable=True,
                output=None,
                method_name="__call__",
                module="mypluginns._plugin",
                qualname="MyPlugin",
            )
        },
        "myns.my_function": {
            "mypluginns.MyPlugin": FunctionDescriptor(
                name="myns.my_function",
                namespace="myns",
                path="mypluginns.my_function",
                exported=True,
                internal=False,
                findable=True,
                output="default",
                method_name="my_function",
                module="mypluginns._plugin",
                qualname="MyPlugin",
            )
        },
    }

    assert mock_plugins["__plugins__"][None] == {
        "myplugin.MyPlugin": PluginDescriptor(
            module="myplugin._plugin",
            qualname="MyPlugin",
            namespace=None,
            path="myplugin",
            findable=True,
            functions=["my_function"],
            exports=["my_function"],
        ),
        "mypluginns.MyPlugin": PluginDescriptor(
            module="mypluginns._plugin",
            qualname="MyPlugin",
            namespace="myns",
            path="mypluginns",
            findable=True,
            functions=["my_function", "__call__"],
            exports=["my_function", "__call__"],
        ),
    }
