from __future__ import annotations

import os
import sys
import textwrap
from functools import reduce
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock, patch

import pytest
from docutils.core import publish_string
from docutils.utils import SystemMessage

from dissect.target.exceptions import PluginError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import EmptyRecord, create_extended_descriptor
from dissect.target.plugin import (
    FunctionDescriptor,
    FunctionDescriptorLookup,
    InternalNamespacePlugin,
    InternalPlugin,
    NamespacePlugin,
    OSPlugin,
    Plugin,
    PluginDescriptor,
    PluginDescriptorLookup,
    PluginRegistry,
    _find_py_files,
    _save_plugin_import_failure,
    alias,
    environment_variable_paths,
    export,
    find_functions,
    find_functions_by_record_field_type,
    functions,
    get_external_module_paths,
    load_modules_from_paths,
    lookup,
    plugins,
)
from dissect.target.plugins.apps.other.env import EnvironmentFilePlugin
from dissect.target.plugins.general.users import UsersPlugin
from dissect.target.plugins.os.default._os import DefaultOSPlugin
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record import Record


def test_save_plugin_import_failure() -> None:
    test_trace = ["test-trace"]
    test_module_name = "test-module"

    with (
        patch("traceback.format_exception", Mock(return_value=test_trace)),
        patch("dissect.target.plugin.PLUGINS", new_callable=PluginRegistry) as mock_plugins,
    ):
        _save_plugin_import_failure(test_module_name)

        assert len(mock_plugins.__failed__) == 1
        assert mock_plugins.__failed__[0].module == test_module_name
        assert mock_plugins.__failed__[0].stacktrace == test_trace


@pytest.mark.parametrize(
    ("env_value", "expected_output"),
    [
        (None, []),
        ("", []),
        (":", [Path(), Path()]),
    ],
)
def test_load_environment_variable(env_value: str | None, expected_output: list[Path]) -> None:
    with patch.object(os, "environ", {"DISSECT_PLUGINS": env_value}):
        assert environment_variable_paths() == expected_output


def test_load_module_paths() -> None:
    assert get_external_module_paths([Path(), Path()]) == [Path()]


def test_load_paths_with_env() -> None:
    with patch.object(os, "environ", {"DISSECT_PLUGINS": ":"}):
        assert get_external_module_paths([Path(), Path()]) == [Path()]


def test_load_environment_variable_empty_string() -> None:
    with patch("dissect.target.plugin._find_py_files") as mocked_find_py_files:
        load_modules_from_paths([])
        mocked_find_py_files.assert_not_called()


def test_load_environment_variable_comma_seperated_string() -> None:
    with patch("dissect.target.plugin._find_py_files") as mocked_find_py_files:
        load_modules_from_paths([Path(), Path()])
        mocked_find_py_files.assert_called_with(Path())


def test_filter_file(tmp_path: Path) -> None:
    file = tmp_path / "hello.py"
    file.touch()

    assert list(_find_py_files(file)) == [file]

    test_file = tmp_path / "non_existent_file"
    assert list(_find_py_files(test_file)) == []

    test_file = tmp_path / "__init__.py"
    test_file.touch()
    assert list(_find_py_files(test_file)) == []


@pytest.mark.parametrize(
    ("filename", "empty_list"),
    [
        ("__init__.py", True),
        ("__pycache__/help.pyc", True),
        ("hello/test.py", False),
    ],
)
def test_filter_directory(tmp_path: Path, filename: str, empty_list: bool) -> None:
    file = tmp_path / filename
    file.parent.mkdir(parents=True, exist_ok=True)
    file.touch()

    if empty_list:
        assert list(_find_py_files(tmp_path)) == []
    else:
        assert file in list(_find_py_files(tmp_path))


@pytest.mark.parametrize(
    ("filename", "expected_module"),
    [
        ("test.py", "test"),
        ("hello_world/help.py", "hello_world.help"),
        ("path/to/file.py", "path.to.file"),
    ],
)
def test_filesystem_module_registration(tmp_path: Path, filename: str, expected_module: str) -> None:
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()

    load_modules_from_paths([tmp_path])

    assert expected_module in sys.modules


def test_plugin_registration(tmp_path: Path) -> None:
    code = """
        from dissect.target.plugin import Plugin, export


        class TestPlugin(Plugin):
            __register__ = False

            def check_compatible(self) -> None:
                return None

            @export(output="default")
            def hello_world(self):
                for x in self.target.fs.iterdir(""):
                    print(f"hello {x}")
    """
    (tmp_path / "plugin.py").write_text(textwrap.dedent(code))

    with patch("dissect.target.plugin.register") as mock_register:
        load_modules_from_paths([tmp_path])

        mock_register.assert_called_once()
        assert mock_register.call_args[0][0].__name__ == "TestPlugin"

    with patch("dissect.target.plugin.register") as mock_register:
        load_modules_from_paths([tmp_path / "plugin.py"])

        mock_register.assert_called_once()
        assert mock_register.call_args[0][0].__name__ == "TestPlugin"


@patch("dissect.target.plugin.PLUGINS", new_callable=PluginRegistry)
def test_plugin_directory(mock_plugins: PluginRegistry, tmp_path: Path) -> None:
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

    assert mock_plugins.__functions__.__regular__ == {
        "my_function": {
            "myplugin.MyPlugin": FunctionDescriptor(
                name="my_function",
                namespace=None,
                path="myplugin.my_function",
                exported=True,
                internal=False,
                findable=True,
                alias=False,
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
                alias=False,
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
                alias=False,
                output="default",
                method_name="my_function",
                module="mypluginns._plugin",
                qualname="MyPlugin",
            )
        },
    }

    assert mock_plugins.__plugins__.__regular__ == {
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


class MockOSWarpPlugin(OSPlugin):
    __exports__ = ("f6",)  # OS exports f6
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
    return_value=PluginRegistry(
        __functions__=FunctionDescriptorLookup(
            __regular__={
                "Warp.f3": {
                    "test.x13.x13": FunctionDescriptor(
                        name="Warp.f3",
                        namespace="Warp",
                        path="test.x13.f3",
                        exported=True,
                        internal=False,
                        findable=True,
                        alias=False,
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
                        alias=False,
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
                        alias=False,
                        output="record",
                        method_name="f22",
                        module="test.x69",
                        qualname="x69",
                    )
                },
            },
            __os__={
                "f6": {
                    "os.warp._os.warp": FunctionDescriptor(
                        name="f6",
                        namespace=None,
                        path="os.warp._os.f6",
                        exported=True,
                        internal=False,
                        findable=True,
                        alias=False,
                        output="record",
                        method_name="f6",
                        module="os.warp._os",
                        qualname="warp",
                    )
                }
            },
        ),
        __ostree__={"os": {"warp": {}}},
    ),
)
@patch("dissect.target.Target", create=True)
@pytest.mark.parametrize(
    ("search", "assert_num_found"),
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
def test_find_functions(target: MagicMock, plugins: dict, search: str, assert_num_found: int) -> None:
    target._os_plugin = MockOSWarpPlugin
    target._os_plugin.__module__ = "dissect.target.plugins.os.warp._os"

    found, _ = find_functions(search, target)
    assert len(found) == assert_num_found


def test_find_functions_windows(target_win: Target) -> None:
    found, _ = find_functions("services", target_win)

    assert len(found) == 1
    assert found[0].name == "services"
    assert found[0].path == "os.windows.services.services"


def test_find_functions_linux(target_linux: Target) -> None:
    found, _ = find_functions("services", target_linux)

    assert len(found) == 1
    assert found[0].name == "services"
    assert found[0].path == "os.unix.linux.services.services"


def test_find_functions_compatible_check(target_linux: Target) -> None:
    """Test if we correctly check for compatibility in ``find_functions`` and ``_filter_compatible``."""

    found, _ = find_functions("*", target_linux, compatibility=True)
    assert "os.unix.log.messages.syslog.syslog" not in [f"{f.path}.{f.name}" for f in found]

    with patch("dissect.target.plugins.apps.browser.chrome.ChromePlugin.check_compatible", return_value=None):
        found, _ = find_functions("*", target_linux, compatibility=True)
        functions = [f.path for f in found]
        assert "apps.browser.chrome.cookies" in functions
        assert "apps.browser.chrome.history" in functions


TestRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/test",
    [
        ("string", "value"),
    ],
)

TestRecord2 = create_extended_descriptor([UserRecordDescriptorExtension])(
    "application/test_other",
    [
        ("varint", "value"),
    ],
)


class _TestNSPlugin(NamespacePlugin):
    __namespace__ = "NS"
    __register__ = False

    @export(record=TestRecord)
    def test_all(self) -> Iterator[TestRecord]:
        # Iterate all functions of all subclasses
        yield from self.test()


class _TestSubPlugin1(_TestNSPlugin):
    __namespace__ = "t1"
    __register__ = False

    @export(record=TestRecord)
    def test(self) -> Iterator[TestRecord]:
        yield TestRecord(value="test1")


class _TestSubPlugin2(_TestNSPlugin):
    __namespace__ = "t2"
    __register__ = False

    @export(record=TestRecord)
    def test(self) -> Iterator[TestRecord]:
        yield TestRecord(value="test2")


class _TestSubPlugin3(_TestSubPlugin2):
    __namespace__ = "t3"
    __register__ = False

    # Override the test() function of t2
    @export(record=TestRecord)
    def test(self) -> Iterator[TestRecord]:
        yield TestRecord(value=self._value())

    def _value(self) -> str:
        return "test3"


class _TestSubPlugin4(_TestSubPlugin3):
    __namespace__ = "t4"
    __register__ = False

    # Do not override the test() function of t3, but change the _value function instead.
    def _value(self) -> str:
        return "test4"

    @export(record=TestRecord)
    def test_other(self) -> Iterator[TestRecord]:
        yield TestRecord(value="test4-other")

    @export(record=TestRecord)
    def test_all(self) -> Iterator[TestRecord]:
        yield TestRecord(value="overridden")


class _TestSubPlugin5(_TestNSPlugin):
    __namespace__ = "t5"
    __register__ = False

    @export(record=TestRecord2)
    def test_other(self) -> Iterator[TestRecord2]:
        yield TestRecord2(value=69)


def test_namespace_plugin(target_win: Target) -> None:
    assert "__subplugins__" in dir(_TestNSPlugin)
    # Rename the test functions to protect them from being filtered by NS

    target_win._register_plugin_functions(_TestSubPlugin1(target_win))
    target_win._register_plugin_functions(_TestSubPlugin2(target_win))
    target_win._register_plugin_functions(_TestSubPlugin3(target_win))
    target_win._register_plugin_functions(_TestSubPlugin4(target_win))
    target_win._register_plugin_functions(_TestSubPlugin5(target_win))
    target_win._register_plugin_functions(_TestNSPlugin(target_win))

    assert len(target_win.NS.__subplugins__) == 5
    assert len(target_win.NS.test.__subplugins__) == 4
    assert target_win.NS.test.__doc__ == "Return test for: t1, t2, t3, t4"
    assert [rd.name for rd in target_win.NS.test.__record__] == ["application/test"]

    assert target_win.NS.test_other.__doc__ == "Return test_other for: t4, t5"
    assert sorted([rd.name for rd in target_win.NS.test_other.__record__]) == [
        "application/test",
        "application/test_other",
    ]
    assert len(target_win.NS.test_other.__subplugins__) == 2

    assert len(list(target_win.NS.test())) == 4
    assert sorted([item.value for item in target_win.NS.test()]) == ["test1", "test2", "test3", "test4"]
    assert sorted([item.value for item in target_win.t1.test()]) == ["test1"]
    assert sorted([item.value for item in target_win.t2.test()]) == ["test2"]
    assert sorted([item.value for item in target_win.t3.test()]) == ["test3"]
    assert sorted([item.value for item in target_win.t4.test()]) == ["test4"]

    # Check whether we can access all subclass functions from the superclass
    assert sorted([item.value for item in target_win.NS.test_all()]) == ["test1", "test2", "test3", "test4"]

    # Check whether we can access the overridden function when explicitly accessing the subplugin
    assert next(target_win.t4.test_all()).value == "overridden"

    with pytest.raises(PluginError, match="Cannot merge namespace methods with different output types"):

        class _TestSubPluginFaulty(_TestNSPlugin):
            __namespace__ = "faulty"
            __register__ = False

            @export(output="yield")
            def test(self) -> Iterator[str]:
                yield "faulty"


@patch("dissect.target.plugin.PLUGINS", new_callable=PluginRegistry)
def test_namespace_plugin_registration(mock_plugins: PluginRegistry) -> None:
    class _TestNSPlugin(NamespacePlugin):
        __namespace__ = "NS"

    class _TestSubPlugin1(_TestNSPlugin):
        __namespace__ = "t1"

        @export(record=TestRecord)
        def test(self) -> None: ...

    assert next(lookup("NS")).exported
    assert next(lookup("NS.test")).exported
    assert next(lookup("t1")).exported
    assert next(lookup("t1.test")).exported


@patch("dissect.target.plugin.PLUGINS", new_callable=PluginRegistry)
def test_namesplace_plugin_multiple_same_module(mock_plugins: PluginRegistry) -> None:
    class NS(NamespacePlugin):
        __namespace__ = "ns"

        def check_compatible(self) -> None:
            return None

    class Foo(NS):
        __namespace__ = "foo"

        @export(output="yield")
        def baz(self) -> Iterator[str]:
            yield from ["foo"]

    class Bar(NS):
        __namespace__ = "bar"

        @export(output="yield")
        def baz(self) -> Iterator[str]:
            yield from ["bar"]

    result, _ = find_functions("*.baz")
    assert len(result) == 2
    assert sorted(desc.name for desc in result) == ["bar.baz", "foo.baz"]


def test_find_plugin_function_default(target_default: Target) -> None:
    found, _ = find_functions("services", target_default)

    assert len(found) == 2
    names = [item.name for item in found]
    assert "services" in names
    assert "services" in names
    paths = [item.path for item in found]
    assert "os.unix.linux.services.services" in paths
    assert "os.windows.services.services" in paths

    found, _ = find_functions("mcafee.msc", target_default)
    assert len(found) == 1
    assert found[0].path == "apps.av.mcafee.msc"

    found, _ = find_functions("webserver.access", target_default)
    assert len(found) == 1
    assert found[0].path == "apps.webserver.webserver.access"


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
    found = ",".join(reduce(lambda rs, el: [*rs, el.method_name], find_functions(pattern, target_win)[0], []))
    assert found == pattern


class _TestIncompatiblePlugin(Plugin):
    def check_compatible(self) -> None:
        raise UnsupportedPluginError("My incompatible plugin error")


def test_incompatible_plugin(target_bare: Target) -> None:
    with pytest.raises(UnsupportedPluginError, match="My incompatible plugin error"):
        target_bare.add_plugin(_TestIncompatiblePlugin)


MOCK_PLUGINS = PluginRegistry(
    __functions__=FunctionDescriptorLookup(
        __regular__={
            "mail": {
                "apps.mail.MailPlugin": FunctionDescriptor(
                    name="mail",
                    namespace=None,
                    path="apps.mail.mail",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
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
                    alias=False,
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
                    alias=False,
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
                    alias=False,
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
                    alias=False,
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
                    alias=False,
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
                    alias=False,
                    output="record",
                    method_name="foobar",
                    module="os.foos.foobar",
                    qualname="FooBarPlugin",
                )
            },
        },
        __os__={
            "generic_os": {
                "os._os.GenericOS": FunctionDescriptor(
                    name="generic_os",
                    namespace=None,
                    path="os._os.generic_os",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
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
                    alias=False,
                    output="record",
                    method_name="foo_os",
                    module="os.fooos._os",
                    qualname="FooOS",
                )
            },
        },
    ),
    __plugins__=PluginDescriptorLookup(
        __regular__={
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
        __os__={
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
    ),
    __ostree__={
        "os": {
            "fooos": {},
        }
    },
)


@pytest.mark.parametrize(
    ("osfilter", "index", "expected_plugins"),
    [
        (
            None,
            "__regular__",
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
            "__regular__",
            [
                "apps.mail",
                "os.apps.app1",
                "os.apps.app2",
            ],
        ),
        (
            "os.fooos._os",
            "__regular__",
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
            "__regular__",
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
    # target with DefaultOSPlugin as OS plugin.
    sentinel_function = "all_with_home"
    has_sentinel_function = False
    for p in default_plugin_plugins:
        if sentinel_function in p.functions:
            has_sentinel_function = True
            break

    assert has_sentinel_function

    default_os_plugin_desc = plugins(osfilter=target_default._os_plugin, index="__os__")

    assert len(list(default_os_plugin_desc)) == 1


def test_function_aliases(target_default: Target) -> None:
    """Test if alias functions are tagged as such correctly."""

    # function that is an alias should have an alias property set to True
    syslog_fd = find_functions("syslog", target_default)[0][0]
    assert syslog_fd
    assert syslog_fd.path == "os.unix.log.messages.syslog"
    assert syslog_fd.exported
    assert syslog_fd.alias

    # function that is not an alias should have an alias property set to False
    messages_fd = find_functions("messages", target_default)[0][0]
    assert messages_fd
    assert messages_fd.path == "os.unix.log.messages.messages"
    assert not messages_fd.alias


def test_function_required_arguments(target_default: Target) -> None:
    """Test if functions with required arguments are tagged as such correctly."""

    # function without any arguments should have an args property with an empty list
    syslog_fd = find_functions("syslog", target_default)[0][0]
    assert syslog_fd
    assert not syslog_fd.args

    # function with an argument should have an args property filled
    envfile_fd = find_functions("envfile", target_default)[0][0]
    assert envfile_fd
    assert envfile_fd.args == [
        (
            ("--env-path",),
            {
                "help": "path to scan environment files in",
                "required": True,
            },
        ),
        (
            ("--extension",),
            {
                "default": "env",
                "help": "extension of files to scan",
            },
        ),
    ]


def test_plugin_runtime_info() -> None:
    plugin_desc = next(p for p in plugins() if p.path == "general.users")
    assert plugin_desc.cls is UsersPlugin

    func_desc = next(p for p in functions() if p.path == "apps.other.env.envfile")
    assert func_desc.cls is EnvironmentFilePlugin
    assert func_desc.func is EnvironmentFilePlugin.envfile
    assert func_desc.record is EnvironmentFilePlugin.envfile.__record__
    assert func_desc.args == EnvironmentFilePlugin.envfile.__args__


def test_find_by_record_field_type(target_default: Target) -> None:
    assert "filesystem.walkfs.walkfs" in [desc.path for desc in find_functions_by_record_field_type("path")]
    assert "apps.other.env.envfile" in [
        desc.path for desc in find_functions_by_record_field_type("path", target_default, compatibility=True)
    ]

    with patch(
        "dissect.target.plugin.functions",
        return_value=[
            FunctionDescriptor(
                name="test",
                namespace=None,
                path="test",
                exported=True,
                internal=False,
                findable=True,
                alias=False,
                output="record",
                method_name="test",
                module="test",
                qualname="Test",
            )
        ],
    ):
        with pytest.raises(PluginError, match="An exception occurred while trying to load a plugin: test"):
            list(find_functions_by_record_field_type("path"))

        assert list(find_functions_by_record_field_type("path", ignore_load_errors=True)) == []


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
    def hostname(self) -> str | None:
        pass

    @export(property=True)
    def ips(self) -> list[str]:
        pass

    @export(property=True)
    def version(self) -> str | None:
        pass

    @export(record=EmptyRecord)
    def users(self) -> list[Record]:
        pass

    @export(property=True)
    def os(self) -> str:
        pass

    @export(property=True)
    def architecture(self) -> str | None:
        pass


class MockOS2(OSPlugin):
    __register__ = False

    @export(property=True)
    def hostname(self) -> str | None:
        """Test docstring hostname."""

    @export(property=True)
    def ips(self) -> list[str]:
        """Test docstring ips."""

    @export(property=True)
    def version(self) -> str | None:
        """Test docstring version."""

    @export(record=EmptyRecord)
    def users(self) -> list[Record]:
        """Test docstring users."""

    @export(property=True)
    def os(self) -> str:
        """Test docstring os."""

    @export(property=True)
    def architecture(self) -> str | None:
        """Test docstring architecture."""


@pytest.mark.parametrize(
    ("subclass", "replaced"),
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
            assert subclass_docstring == f"Test docstring {method_name}."


class _TestInternalPlugin(InternalPlugin):
    def test(self) -> None:
        pass


def test_internal_plugin() -> None:
    assert "test" not in _TestInternalPlugin.__exports__
    assert "test" in _TestInternalPlugin.__functions__


class _TestInternalNamespacePlugin(InternalNamespacePlugin):
    __namespace__ = "NS"

    def test(self) -> None:
        pass


def test_internal_namespace_plugin() -> None:
    assert "__subplugins__" in dir(_TestInternalNamespacePlugin)
    assert "test" not in _TestInternalNamespacePlugin.__exports__
    assert "test" in _TestInternalNamespacePlugin.__functions__


class ExampleFooPlugin(Plugin):
    """Example Foo Plugin."""

    __register__ = False

    def check_compatible(self) -> None:
        return

    @export
    @alias("bar")
    @alias(name="baz")
    def foo(self) -> Iterator[str]:
        """Yield foo!."""
        yield "foo!"


def test_plugin_alias(target_bare: Target) -> None:
    """Test ``@alias`` decorator behaviour."""
    target_bare.add_plugin(ExampleFooPlugin)
    assert target_bare.has_function("foo")
    assert target_bare.foo.__aliases__ == ["baz", "bar"]
    assert target_bare.has_function("bar")
    assert target_bare.has_function("baz")
    assert list(target_bare.foo()) == list(target_bare.bar()) == list(target_bare.baz())


@pytest.mark.parametrize(
    "descriptor",
    find_functions("*", Target(), compatibility=False, show_hidden=True)[0],
    ids=lambda d: d.path,
)
def test_exported_plugin_format(descriptor: FunctionDescriptor) -> None:
    """This test checks plugin style guide conformity for all exported plugins.

    Resources:
        - https://docs.dissect.tools/en/latest/contributing/style-guide.html
    """
    # Ignore DefaultOSPlugin and NamespacePlugin instances
    if descriptor.cls.__base__ is NamespacePlugin or descriptor.cls is DefaultOSPlugin:
        return

    # Plugin method should specify what it returns
    assert descriptor.output in ["record", "yield", "default", "none"], (
        f"Invalid output_type for function {descriptor.func.__qualname__}"
    )

    annotations = None

    if hasattr(descriptor.func, "__annotations__"):
        annotations = descriptor.func.__annotations__

    elif isinstance(descriptor.func, property):
        annotations = descriptor.func.fget.__annotations__

    # Plugin method should have a return annotation
    assert annotations
    assert "return" in annotations, f"No return type annotation for function {descriptor.func.__qualname__}"

    # TODO: Check if the annotations make sense with the provided output_type

    # Plugin method should have a docstring
    method_doc_str = descriptor.func.__doc__
    assert isinstance(method_doc_str, str), f"No docstring for function {descriptor.func.__qualname__}"
    assert method_doc_str != "", f"Empty docstring for function {descriptor.func.__qualname__}"

    # The method docstring should compile to rst without warnings
    assert_valid_rst(method_doc_str)

    # Plugin class should have a docstring
    class_doc_str = descriptor.cls.__doc__
    assert isinstance(class_doc_str, str), f"No docstring for class {descriptor.cls.__name__}"
    assert class_doc_str != "", f"Empty docstring for class {descriptor.cls.__name__}"

    # The class docstring should compile to rst without warnings
    assert_valid_rst(class_doc_str)

    # Arguments of the plugin should define their type and if they are required (explicitly or implicitly).
    for arg in descriptor.args:
        names, settings = arg
        is_bool_action = settings.get("action", "") in (
            "store_true",
            "store_false",
        )

        assert names, f"No argument names for argument of function {descriptor.func.__qualname__}"
        assert sorted(names, key=len) == list(names), (
            f"Argument names {names!r} for function {descriptor.func.__qualname__} should specify short form first"
        )

        assert settings.get("default", 1) is not None, (
            f"Superfluous default of None for argument {names[0]} in function {descriptor.func.__qualname__}: "
            "default is implied as None already."
        )

        assert settings.get("help"), f"No help text for argument {names[0]} in function {descriptor.func.__qualname__}"

        dest = settings.get("dest") or names[-1].strip("-").replace("-", "_")
        assert dest in annotations, (
            f"Missing type annotation for argument {dest} in function {descriptor.func.__qualname__}"
        )

        # TODO: More strictly check type annotation, use a contains right now to also match optionals
        type_ = "bool" if is_bool_action else getattr(settings.get("type"), "__name__", "str")
        assert type_ in annotations[dest], (
            f"Invalid type annotation for argument {dest} in function {descriptor.func.__qualname__} "
            f"({annotations[dest]} instead of {type_})"
        )

        assert settings.get("type") is not str, (
            f"Superfluous type of str for argument {names[0]} in function {descriptor.func.__qualname__}: "
            "type is implied as str by default."
        )

        # Inverse checks

        if settings.get("required"):
            assert not settings.get("default"), (
                "It does not make sense to set an argument to required and have a default value"
                f"in {names[0]} in function {descriptor.func.__qualname__}"
            )

        if "required" in settings:
            assert settings.get("required"), (
                f"Superfluous required of False for argument {names[0]} in function {descriptor.func.__qualname__}: "
                "required is implied as False already."
            )

        if is_bool_action:
            assert "type" not in settings, (
                f"Type should not be set for store_true or store_false in {names[0]} in "
                f"function {descriptor.func.__qualname__}: "
                "type is implied as boolean already."
            )

            assert "default" not in settings, (
                f"Default should not be set for store_true or store_false in {names[0]} in "
                f"function {descriptor.func.__qualname__}: "
                "default is implied as opposite boolean already."
            )


def assert_valid_rst(src: str) -> None:
    """Attempts to compile the given string to rst."""

    try:
        publish_string(src, settings_overrides={"halt_level": 2})

    except SystemMessage as e:
        # Limited context was provided to docutils, so some exceptions could incorrectly be raised.
        # We can assume that if the rst is truly invalid this will also be caught by `tox -e build-docs`.
        if "Unknown interpreted text role" not in str(e):
            pytest.fail(f"Invalid rst: {e}", pytrace=False)
