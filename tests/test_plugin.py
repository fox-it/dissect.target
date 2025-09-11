from __future__ import annotations

import os
import sys
import textwrap
from functools import reduce
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest
from docutils.core import publish_string
from docutils.utils import SystemMessage
from flow.record import RecordDescriptor

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
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.plugins.os.unix.linux.debian._os import DebianPlugin
from dissect.target.plugins.os.unix.linux.fortios._os import FortiOSPlugin
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record import Record
    from pytest_benchmark.fixture import BenchmarkFixture


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
                output="record",
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


@patch("dissect.target.plugin.PLUGINS", new_callable=PluginRegistry)
def test_nested_namespace_getattr(mock_plugins: PluginRegistry, target_bare: Target) -> None:
    class Foo(Plugin):
        __namespace__ = "foo"

        @export(output="yield")
        def buzz(self) -> Iterator[str]:
            yield from ["buzz"]

    class FooBar(Plugin):
        __namespace__ = "foo.bar"

        @export(output="yield")
        def bazz(self) -> Iterator[str]:
            yield from ["bazz1"]

        @export(output="yield")
        def bar(self) -> Iterator[str]:
            yield from ["bar1"]

    class FooBaz(Plugin):
        __namespace__ = "foo.baz"

        @export(output="yield")
        def bazz(self) -> Iterator[str]:
            yield from ["bazz2"]

        @export(output="yield")
        def bar(self) -> Iterator[str]:
            yield from ["bar2"]

    for plugin in [Foo, FooBar, FooBaz]:
        target_bare._register_plugin_functions(plugin(target_bare))

    assert isinstance(target_bare.foo, Foo)
    assert isinstance(target_bare.foo.bar, FooBar)
    assert isinstance(target_bare.foo.baz, FooBaz)
    assert hasattr(target_bare.foo.bar, "bazz")

    with pytest.raises(AttributeError):
        target_bare.foo.bazz()

    with pytest.raises(AttributeError):
        target_bare.foo.bar.foo()

    # Test whether we can access the plugin this way
    assert next(target_bare.foo.bar.bazz()) == "bazz1"
    assert next(target_bare.foo.bar.bar()) == "bar1"
    assert next(target_bare.foo.baz.bazz()) == "bazz2"
    assert next(target_bare.foo.baz.bar()) == "bar2"
    assert next(target_bare.foo.buzz()) == "buzz"


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


# A realistic slimmed down mock of a PluginRegistry
MOCK_PLUGINS = PluginRegistry(
    __plugins__=PluginDescriptorLookup(
        __regular__={
            # Non-OS, regular
            "general.osinfo.OSInfoPlugin": PluginDescriptor(
                module="dissect.target.plugins.general.osinfo",
                qualname="OSInfoPlugin",
                namespace=None,
                path="general.osinfo",
                findable=True,
                functions=["osinfo"],
                exports=["osinfo"],
            ),
            # Non-OS, with namespace
            "apps.chat.chat.ChatPlugin": PluginDescriptor(
                module="dissect.target.plugins.apps.chat.chat",
                qualname="ChatPlugin",
                namespace="chat",
                path="apps.chat.chat",
                findable=False,
                functions=["history", "__call__"],
                exports=["history", "__call__"],
            ),
            "apps.chat.msn.MSNPlugin": PluginDescriptor(
                module="dissect.target.plugins.apps.chat.msn",
                qualname="MSNPlugin",
                namespace="msn",
                path="apps.chat.msn",
                findable=True,
                functions=["history", "__call__"],
                exports=["history", "__call__"],
            ),
            # OS, regular
            "os.windows.generic.GenericPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.windows.generic",
                qualname="GenericPlugin",
                namespace=None,
                path="os.windows.generic",
                findable=True,
                functions=["domain"],
                exports=["domain"],
            ),
            "os.unix.cronjobs.CronjobPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.unix.cronjobs",
                qualname="CronjobPlugin",
                namespace=None,
                path="os.unix.cronjobs",
                findable=True,
                functions=["cronjobs"],
                exports=["cronjobs"],
            ),
            "os.windows.regf.runkeys.RunKeysPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.windows.regf.runkeys",
                qualname="RunKeysPlugin",
                namespace=None,
                path="os.windows.regf.runkeys",
                findable=True,
                functions=["runkeys"],
                exports=["runkeys"],
            ),
            # OS, shared name
            "os.unix.linux.services.ServicesPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.unix.linux.services",
                qualname="ServicesPlugin",
                namespace=None,
                path="os.unix.linux.services",
                findable=True,
                functions=["initd", "services", "systemd"],
                exports=["services"],
            ),
            "os.windows.services.ServicesPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.windows.services",
                qualname="ServicesPlugin",
                namespace=None,
                path="os.windows.services",
                findable=True,
                functions=["services"],
                exports=["services"],
            ),
            # OS, with default
            "os.default.locale.LocalePlugin": PluginDescriptor(
                module="dissect.target.plugins.os.default.locale",
                qualname="LocalePlugin",
                namespace=None,
                path="os.default.locale",
                findable=True,
                functions=["timezone"],
                exports=["timezone"],
            ),
            "os.unix.locale.UnixLocalePlugin": PluginDescriptor(
                module="dissect.target.plugins.os.unix.locale",
                qualname="UnixLocalePlugin",
                namespace=None,
                path="os.unix.locale",
                findable=True,
                functions=["timezone"],
                exports=["timezone"],
            ),
            "os.unix.linux.fortios.locale.FortiOSLocalePlugin": PluginDescriptor(
                module="dissect.target.plugins.os.unix.linux.fortios.locale",
                qualname="FortiOSLocalePlugin",
                namespace=None,
                path="os.unix.linux.fortios.locale",
                findable=True,
                functions=["timezone"],
                exports=["timezone"],
            ),
            "os.windows.locale.WindowsLocalePlugin": PluginDescriptor(
                module="dissect.target.plugins.os.windows.locale",
                qualname="WindowsLocalePlugin",
                namespace=None,
                path="os.windows.locale",
                findable=True,
                functions=["timezone"],
                exports=["timezone"],
            ),
        },
        __os__={
            "os.default._os.DefaultOSPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.default._os",
                qualname="DefaultOSPlugin",
                namespace=None,
                path="os.default._os",
                findable=True,
                functions=["hostname", "os", "os_tree"],
                exports=["hostname", "os"],
            ),
            "os.unix._os.UnixPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.unix._os",
                qualname="UnixPlugin",
                namespace=None,
                path="os.unix._os",
                findable=True,
                functions=["hostname", "domain", "os", "os_tree"],
                exports=["hostname", "domain", "os"],
            ),
            "os.unix.linux._os.LinuxPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.unix.linux._os",
                qualname="LinuxPlugin",
                namespace=None,
                path="os.unix.linux._os",
                findable=True,
                functions=["hostname", "domain", "os", "os_tree"],
                exports=["hostname", "domain", "os"],
            ),
            "os.unix.linux.fortios._os.FortiOSPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.unix.linux.fortios._os",
                qualname="FortiOSPlugin",
                namespace=None,
                path="os.unix.linux.fortios._os",
                findable=True,
                functions=["hostname", "domain", "os", "os_tree"],
                exports=["hostname", "domain", "os"],
            ),
            "os.windows._os.WindowsPlugin": PluginDescriptor(
                module="dissect.target.plugins.os.windows._os",
                qualname="WindowsPlugin",
                namespace=None,
                path="os.windows._os",
                findable=True,
                functions=["hostname", "os", "os_tree"],
                exports=["hostname", "os"],
            ),
        },
        __child__={},
    ),
    __functions__=FunctionDescriptorLookup(
        __regular__={
            # Non-OS, regular
            "osinfo": {
                "general.osinfo.OSInfoPlugin": FunctionDescriptor(
                    name="osinfo",
                    namespace=None,
                    path="general.osinfo.osinfo",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="record",
                    method_name="osinfo",
                    module="dissect.target.plugins.general.osinfo",
                    qualname="OSInfoPlugin",
                )
            },
            # Non-OS, with namespace
            "chat": {
                "apps.chat.chat.ChatPlugin": FunctionDescriptor(
                    name="chat",
                    namespace="chat",
                    path="apps.chat.chat",
                    exported=True,
                    internal=False,
                    findable=False,
                    alias=False,
                    output="record",
                    method_name="__call__",
                    module="dissect.target.plugins.apps.chat.chat",
                    qualname="ChatPlugin",
                )
            },
            "chat.history": {
                "apps.chat.chat.ChatPlugin": FunctionDescriptor(
                    name="chat.history",
                    namespace="chat",
                    path="apps.chat.chat.history",
                    exported=True,
                    internal=False,
                    findable=False,
                    alias=False,
                    output="record",
                    method_name="history",
                    module="dissect.target.plugins.apps.chat.chat",
                    qualname="ChatPlugin",
                )
            },
            "msn": {
                "apps.chat.msn.MSNPlugin": FunctionDescriptor(
                    name="msn",
                    namespace="msn",
                    path="apps.chat.msn",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="record",
                    method_name="__call__",
                    module="dissect.target.plugins.apps.chat.msn",
                    qualname="MSNPlugin",
                )
            },
            "msn.history": {
                "apps.chat.msn.MSNPlugin": FunctionDescriptor(
                    name="msn.history",
                    namespace="msn",
                    path="apps.chat.msn.history",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="record",
                    method_name="history",
                    module="dissect.target.plugins.apps.chat.msn",
                    qualname="MSNPlugin",
                )
            },
            # OS, regular
            "domain": {
                "os.windows.generic.GenericPlugin": FunctionDescriptor(
                    name="domain",
                    namespace=None,
                    path="os.windows.generic.domain",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="domain",
                    module="dissect.target.plugins.os.windows.generic",
                    qualname="GenericPlugin",
                )
            },
            "cronjobs": {
                "os.unix.cronjobs.CronjobPlugin": FunctionDescriptor(
                    name="cronjobs",
                    namespace=None,
                    path="os.unix.cronjobs.cronjobs",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="record",
                    method_name="cronjobs",
                    module="dissect.target.plugins.os.unix.cronjobs",
                    qualname="CronjobPlugin",
                )
            },
            "runkeys": {
                "os.windows.regf.runkeys.RunKeysPlugin": FunctionDescriptor(
                    name="runkeys",
                    namespace=None,
                    path="os.windows.regf.runkeys.runkeys",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="record",
                    method_name="runkeys",
                    module="dissect.target.plugins.os.windows.regf.runkeys",
                    qualname="RunKeysPlugin",
                )
            },
            # OS, shared name
            "services": {
                "os.windows.services.ServicesPlugin": FunctionDescriptor(
                    name="services",
                    namespace=None,
                    path="os.windows.services.services",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="record",
                    method_name="services",
                    module="dissect.target.plugins.os.windows.services",
                    qualname="ServicesPlugin",
                ),
                "os.unix.linux.services.ServicesPlugin": FunctionDescriptor(
                    name="services",
                    namespace=None,
                    path="os.unix.linux.services.services",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="record",
                    method_name="services",
                    module="dissect.target.plugins.os.unix.linux.services",
                    qualname="ServicesPlugin",
                ),
            },
            # OS, with default
            "timezone": {
                "os.default.locale.LocalePlugin": FunctionDescriptor(
                    name="timezone",
                    namespace=None,
                    path="os.default.locale.timezone",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="timezone",
                    module="dissect.target.plugins.os.default.locale",
                    qualname="LocalePlugin",
                ),
                "os.unix.locale.UnixLocalePlugin": FunctionDescriptor(
                    name="timezone",
                    namespace=None,
                    path="os.unix.locale.timezone",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="timezone",
                    module="dissect.target.plugins.os.unix.locale",
                    qualname="UnixLocalePlugin",
                ),
                "os.unix.linux.fortios.locale.FortiOSLocalePlugin": FunctionDescriptor(
                    name="timezone",
                    namespace=None,
                    path="os.unix.linux.fortios.locale.timezone",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="timezone",
                    module="dissect.target.plugins.os.unix.linux.fortios.locale",
                    qualname="FortiOSLocalePlugin",
                ),
                "os.windows.locale.WindowsLocalePlugin": FunctionDescriptor(
                    name="timezone",
                    namespace=None,
                    path="os.windows.locale.timezone",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="timezone",
                    module="dissect.target.plugins.os.windows.locale",
                    qualname="WindowsLocalePlugin",
                ),
            },
        },
        __os__={
            "hostname": {
                "os.default._os.DefaultOSPlugin": FunctionDescriptor(
                    name="hostname",
                    namespace=None,
                    path="os.default._os.hostname",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="hostname",
                    module="dissect.target.plugins.os.default._os",
                    qualname="DefaultOSPlugin",
                ),
                "os.unix._os.UnixPlugin": FunctionDescriptor(
                    name="hostname",
                    namespace=None,
                    path="os.unix._os.hostname",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="hostname",
                    module="dissect.target.plugins.os.unix._os",
                    qualname="UnixPlugin",
                ),
                "os.unix.linux._os.LinuxPlugin": FunctionDescriptor(
                    name="hostname",
                    namespace=None,
                    path="os.unix.linux._os.hostname",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="hostname",
                    module="dissect.target.plugins.os.unix.linux._os",
                    qualname="LinuxPlugin",
                ),
                "os.unix.linux.fortios._os.FortiOSPlugin": FunctionDescriptor(
                    name="hostname",
                    namespace=None,
                    path="os.unix.linux.fortios._os.hostname",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="hostname",
                    module="dissect.target.plugins.os.unix.linux.fortios._os",
                    qualname="FortiOSPlugin",
                ),
                "os.windows._os.WindowsPlugin": FunctionDescriptor(
                    name="hostname",
                    namespace=None,
                    path="os.windows._os.hostname",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="hostname",
                    module="dissect.target.plugins.os.windows._os",
                    qualname="WindowsPlugin",
                ),
            },
            "os": {
                "os.default._os.DefaultOSPlugin": FunctionDescriptor(
                    name="os",
                    namespace=None,
                    path="os.default._os.os",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="os",
                    module="dissect.target.plugins.os.default._os",
                    qualname="DefaultOSPlugin",
                ),
                "os.unix._os.UnixPlugin": FunctionDescriptor(
                    name="os",
                    namespace=None,
                    path="os.unix._os.os",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="os",
                    module="dissect.target.plugins.os.unix._os",
                    qualname="UnixPlugin",
                ),
                "os.unix.linux._os.LinuxPlugin": FunctionDescriptor(
                    name="os",
                    namespace=None,
                    path="os.unix.linux._os.os",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="os",
                    module="dissect.target.plugins.os.unix.linux._os",
                    qualname="LinuxPlugin",
                ),
                "os.unix.linux.fortios._os.FortiOSPlugin": FunctionDescriptor(
                    name="os",
                    namespace=None,
                    path="os.unix.linux.fortios._os.os",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="os",
                    module="dissect.target.plugins.os.unix.linux.fortios._os",
                    qualname="FortiOSPlugin",
                ),
                "os.windows._os.WindowsPlugin": FunctionDescriptor(
                    name="os",
                    namespace=None,
                    path="os.windows._os.os",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="os",
                    module="dissect.target.plugins.os.windows._os",
                    qualname="WindowsPlugin",
                ),
            },
            "domain": {
                "os.unix._os.UnixPlugin": FunctionDescriptor(
                    name="domain",
                    namespace=None,
                    path="os.unix._os.domain",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="domain",
                    module="dissect.target.plugins.os.unix._os",
                    qualname="UnixPlugin",
                ),
                "os.unix.linux._os.LinuxPlugin": FunctionDescriptor(
                    name="domain",
                    namespace=None,
                    path="os.unix.linux._os.domain",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="domain",
                    module="dissect.target.plugins.os.unix.linux._os",
                    qualname="LinuxPlugin",
                ),
                "os.unix.linux.fortios._os.FortiOSPlugin": FunctionDescriptor(
                    name="domain",
                    namespace=None,
                    path="os.unix.linux.fortios._os.domain",
                    exported=True,
                    internal=False,
                    findable=True,
                    alias=False,
                    output="default",
                    method_name="domain",
                    module="dissect.target.plugins.os.unix.linux.fortios._os",
                    qualname="FortiOSPlugin",
                ),
            },
        },
        __child__={},
    ),
    __ostree__={
        "os": {
            "default": {},
            "unix": {
                "linux": {
                    "fortios": {},
                }
            },
            "windows": {},
        }
    },
    __failed__=[],
)


@pytest.mark.parametrize(
    ("osfilter", "index", "expected_plugins"),
    [
        (
            None,
            "__regular__",
            [
                "dissect.target.plugins.general.osinfo",
                "dissect.target.plugins.apps.chat.chat",
                "dissect.target.plugins.apps.chat.msn",
                "dissect.target.plugins.os.windows.generic",
                "dissect.target.plugins.os.unix.cronjobs",
                "dissect.target.plugins.os.windows.regf.runkeys",
                "dissect.target.plugins.os.windows.services",
                "dissect.target.plugins.os.unix.linux.services",
                "dissect.target.plugins.os.default.locale",
                "dissect.target.plugins.os.unix.locale",
                "dissect.target.plugins.os.unix.linux.fortios.locale",
                "dissect.target.plugins.os.windows.locale",
            ],
        ),
        (
            None,
            "__os__",
            [
                "dissect.target.plugins.os.default._os",
                "dissect.target.plugins.os.unix._os",
                "dissect.target.plugins.os.unix.linux._os",
                "dissect.target.plugins.os.unix.linux.fortios._os",
                "dissect.target.plugins.os.windows._os",
            ],
        ),
        (
            "os.unix._os",
            "__regular__",
            [
                "dissect.target.plugins.general.osinfo",
                "dissect.target.plugins.apps.chat.chat",
                "dissect.target.plugins.apps.chat.msn",
                "dissect.target.plugins.os.unix.cronjobs",
                "dissect.target.plugins.os.unix.locale",
            ],
        ),
        (
            "os.unix.linux.fortios._os",
            "__regular__",
            [
                "dissect.target.plugins.general.osinfo",
                "dissect.target.plugins.apps.chat.chat",
                "dissect.target.plugins.apps.chat.msn",
                "dissect.target.plugins.os.unix.cronjobs",
                "dissect.target.plugins.os.unix.locale",
                "dissect.target.plugins.os.unix.linux.services",
                "dissect.target.plugins.os.unix.linux.fortios.locale",
            ],
        ),
        (
            "os.windows._os",
            "__regular__",
            [
                "dissect.target.plugins.general.osinfo",
                "dissect.target.plugins.apps.chat.chat",
                "dissect.target.plugins.apps.chat.msn",
                "dissect.target.plugins.os.windows.generic",
                "dissect.target.plugins.os.windows.regf.runkeys",
                "dissect.target.plugins.os.windows.services",
                "dissect.target.plugins.os.windows.locale",
            ],
        ),
        (
            "os.bar._os",
            "__regular__",
            [
                "dissect.target.plugins.general.osinfo",
                "dissect.target.plugins.apps.chat.chat",
                "dissect.target.plugins.apps.chat.msn",
            ],
        ),
        (
            "os.windows._os",
            "__os__",
            [],
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

        assert sorted(desc.module for desc in plugin_descriptors) == sorted(expected_plugins)


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


@pytest.mark.parametrize(
    ("os_plugin", "pattern", "expected_paths"),
    [
        # Direct match
        (DefaultOSPlugin, "osinfo", ["general.osinfo.osinfo"]),
        # Direct match with namespace, regardless of `findable` status
        (DefaultOSPlugin, "chat.history", ["apps.chat.chat.history"]),
        (DefaultOSPlugin, "msn.history", ["apps.chat.msn.history"]),
        # Find with tree search using wildcard
        (DefaultOSPlugin, "general.*", ["general.osinfo.osinfo"]),
        # Find with tree search using implicit wildcard
        (DefaultOSPlugin, "general.osinfo", ["general.osinfo.osinfo"]),
        # Find with exact tree match
        (DefaultOSPlugin, "general.osinfo.osinfo", ["general.osinfo.osinfo"]),
        # Find with tree search using more complicated patterns
        (DefaultOSPlugin, "general.[!o]*", []),
        (DefaultOSPlugin, "general.[!x]*", ["general.osinfo.osinfo"]),
        (DefaultOSPlugin, "general.??????.??????", ["general.osinfo.osinfo"]),
        # Namespaces do not match
        (DefaultOSPlugin, "chat.*", []),
        # Part of module paths do not match
        (DefaultOSPlugin, "generic", []),
        # OS direct match only matches within the same OS plugin
        (DefaultOSPlugin, "hostname", ["os.default._os.hostname"]),
        (WindowsPlugin, "hostname", ["os.windows._os.hostname"]),
        (LinuxPlugin, "hostname", ["os.unix.linux._os.hostname", "os.unix._os.hostname"]),
        # OS tree search only matches within the same OS plugin
        (DefaultOSPlugin, "os.windows._os.hostname", []),
        (WindowsPlugin, "os.default._os.hostname", []),
        (DefaultOSPlugin, "os.*.hostname", ["os.default._os.hostname"]),
        (WindowsPlugin, "os.*.hostname", ["os.windows._os.hostname"]),
        # # "os" hits the direct match, not the tree search
        (DefaultOSPlugin, "os", ["os.default._os.os"]),
        (WindowsPlugin, "os", ["os.windows._os.os"]),
        # Wildcard matches all regular functions and OS functions (within the same OS)
        (
            DefaultOSPlugin,
            "*",
            [
                "os.unix.linux.fortios.locale.timezone",
                "os.windows.regf.runkeys.runkeys",
                "os.unix.linux.services.services",
                "apps.chat.msn.history",
                "os.windows.generic.domain",
                "os.unix.cronjobs.cronjobs",
                "os.windows.services.services",
                "os.default.locale.timezone",
                "os.unix.locale.timezone",
                "os.windows.locale.timezone",
                "os.default._os.hostname",
                "os.default._os.os",
                "general.osinfo.osinfo",
            ],
        ),
        (
            WindowsPlugin,
            "*",
            [
                "os.windows.regf.runkeys.runkeys",
                "apps.chat.msn.history",
                "os.windows.generic.domain",
                "os.windows.services.services",
                "os.windows.locale.timezone",
                "os.windows._os.hostname",
                "os.windows._os.os",
                "general.osinfo.osinfo",
            ],
        ),
        # Some OS functions only exist on certain OS plugins
        (LinuxPlugin, "os.*.domain", ["os.unix.linux._os.domain", "os.unix._os.domain"]),
        # # Some plugins have complicated paths (i.e. LocalePlugin)
        (LinuxPlugin, "timezone", ["os.unix.locale.timezone"]),
        (FortiOSPlugin, "timezone", ["os.unix.linux.fortios.locale.timezone", "os.unix.locale.timezone"]),
        # Some plugins have overlapping names (i.e. "services")
        (FortiOSPlugin, "services", ["os.unix.linux.services.services"]),
        (WindowsPlugin, "services", ["os.windows.services.services"]),
    ],
)
def test_find_functions(os_plugin: type[OSPlugin], pattern: str, expected_paths: list[str]) -> None:
    with patch("dissect.target.plugin._get_plugins", return_value=MOCK_PLUGINS):
        target = Target()
        target._os_plugin = os_plugin

        found, _ = find_functions(pattern, target)
        assert [desc.path for desc in found] == expected_paths


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


@pytest.mark.benchmark
def test_benchmark_functions_compatible_check(target_unix_users: Target, benchmark: BenchmarkFixture) -> None:
    """Benchmark ``_filter_compatible`` performance."""
    benchmark(lambda: find_functions("*", target_unix_users, compatibility=True))


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


@pytest.mark.parametrize(
    argnames=("os_plugin", "results"),
    argvalues=[
        (LinuxPlugin, ["linux", "unix"]),
        (FortiOSPlugin, ["fortios", "linux", "unix"]),
        (DebianPlugin, ["linux", "unix"]),
    ],
)
def test_os_tree(target_bare: Target, os_plugin: type[OSPlugin], results: list[str]) -> None:
    """Test if we correctly return the OS name tree."""
    target_bare._os_plugin = os_plugin
    target_bare.apply()
    assert target_bare.os_tree() == results


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

    References:
        - https://docs.dissect.tools/en/latest/contributing/style-guide.html
    """
    # Ignore DefaultOSPlugin, NamespacePlugin and OSPlugin instances
    if issubclass(descriptor.cls, (NamespacePlugin, OSPlugin)) or descriptor.cls is DefaultOSPlugin:
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

    # The method docstring should follow our conventions
    assert_compliant_rst(method_doc_str)

    # Plugin class should have a docstring
    class_doc_str = descriptor.cls.__doc__
    assert isinstance(class_doc_str, str), f"No docstring for class {descriptor.cls.__name__}"
    assert class_doc_str != "", f"Empty docstring for class {descriptor.cls.__name__}"

    # The class docstring should compile to rst without warnings
    assert_valid_rst(class_doc_str)

    # The class docstring should follow our conventions
    assert_compliant_rst(class_doc_str)

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


def test_plugin_record_field_consistency() -> None:
    """Test if exported plugin functions yielding records do not have conflicting field names and types.

    For example, take the following TargetRecordDescriptors for plugin X, Y and Z::

        RecordX = TargetRecordDescriptor("record/x", [("varint", "my_field")])
        RecordY = TargetRecordDescriptor("record/y", [("path", "my_field")])
        RecordZ = TargetRecordDescriptor("record/y", [("string", "my_field")])

    The ``RecordX`` descriptor will fail in this test, since the field ``my_field`` cannot be of type ``varint``
    while also being used as ``string`` (and ``path``). The ``RecordY`` and ``RecordZ`` descriptors do not conflict,
    since the types ``path`` and ``string`` translate to the same ``wildcard`` type.

    Uses ``FIELD_TYPES_MAP`` which is loosely based on flow.record and ElasticSearch field types.

    References:
        - https://elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
        - https://github.com/fox-it/flow.record/tree/main/flow/record/fieldtypes
        - https://github.com/JSCU-NL/dissect-elastic
    """

    seen_field_names: set[str] = set()
    seen_field_types: dict[str, tuple[str | None, RecordDescriptor]] = {}
    inconsistencies: set[str] = set()

    FIELD_TYPES_MAP = {
        # strings
        "string": "string",
        "stringlist": "string",
        "wstring": "string",
        "path": "string",
        "uri": "string",
        "command": "string",
        "dynamic": "string",
        # ints
        "varint": "int",
        "filesize": "int",
        "uint32": "int",
        "uint16": "int",
        "float": "float",
        # ip / cidr
        "net.ipaddress": "ip",
        "net.ipnetwork": "ip_range",
        "net.ipinterface": "ip_range",
        # dates
        "datetime": "datetime",
        # other
        "boolean": "boolean",
        "bytes": "binary",
        "digest": "keyword",
    }

    for descriptor in find_functions("*", Target(), compatibility=False, show_hidden=True)[0]:
        # Test if plugin function record fields make sense and do not conflict with other records.
        if descriptor.output == "record" and hasattr(descriptor, "record"):
            # Functions can yield a single record or a list of records.
            records = descriptor.record if isinstance(descriptor.record, list) else [descriptor.record]

            for record in records:
                assert isinstance(record, RecordDescriptor), (
                    f"{record!r} of function {descriptor!r} is not of type RecordDescriptor"
                )
                if record.name != "empty":
                    assert record.fields, f"{record!r} has no fields"

                for name, field in record.fields.items():
                    # Make sure field names have the same type when translated. This check does not save multiple field
                    # name and typenames, this is a bare-minumum check only.

                    # We only care about the field type, not if it is a list of that type.
                    field_typename = field.typename.replace("[]", "")

                    assert field_typename in FIELD_TYPES_MAP, (
                        f"Field type {field_typename} is not mapped in FIELD_TYPES_MAP, please add it manually."
                    )

                    if name in seen_field_names:
                        seen_typename, seen_record = seen_field_types[name]
                        if FIELD_TYPES_MAP[seen_typename] != FIELD_TYPES_MAP[field_typename]:
                            inconsistencies.add(
                                f"<{record.name} ({field.typename!r}, '{name}')> is duplicate mismatch of <{seen_record.name} ({seen_typename!r}, '{name}')>"  # noqa: E501
                            )

                    else:
                        seen_field_names.add(name)
                        seen_field_types[name] = (field_typename, record)

    if inconsistencies:
        pytest.fail(
            f"Found {len(inconsistencies)} inconsistencies in RecordDescriptors:\n" + "\n".join(inconsistencies)
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


def assert_compliant_rst(src: str) -> None:
    """Makes sure that the given rst docstring follows the project's conventions."""

    # Explicit message stating we want References instead of Resources to prevent confusion
    if "Resources:\n" in src:
        pytest.fail(f"Invalid rst: docstring contains 'Resources' instead of 'References': {src!r}", pytrace=False)

    # Generic message stating lists should start with References (assumes lists always have at least one 'http')
    if "- http" in src and "References:\n" not in src:
        pytest.fail(f"Invalid rst: docstring contains list but does not mention 'References': {src!r}", pytrace=False)

    # Make sure we use stripes instead of bullets (assumes lists always have at least one 'http')
    if "* http" in src:
        pytest.fail(f"Invalid rst: docstring contains bullet instead of dash in list: {src!r}", pytrace=False)


@pytest.mark.parametrize(
    "descriptor",
    [descriptor for descriptor in plugins() if descriptor.namespace and "." in descriptor.namespace],
    ids=lambda descriptor: descriptor.namespace,
)
def test_nested_namespace_consistency(descriptor: PluginDescriptor) -> None:
    """Test whether all parts of nested namespaces exist and that there are no conflicts with other functions."""

    parts = descriptor.namespace.split(".")
    for i in range(len(parts)):
        part = ".".join(parts[: i + 1])
        result = list(lookup(part))

        if not result:
            pytest.fail(f"Unreachable namespace {descriptor.namespace!r}, namespace {part!r} does not exist.")

        if len(result) > 1:
            conflicts = ", ".join(
                f"{desc.name} ({desc.module}.{desc.qualname})" for desc in result if desc.namespace != part
            )
            pytest.fail(f"Namespace name {descriptor.namespace!r} has conflicts with function name: {conflicts}")


@pytest.mark.parametrize(
    "descriptor",
    # Match plugin classes which are a *direct* base of NamespacePlugin only using :meth:`Plugin.__bases__`,
    # instead of using ``issubclass`` which would also yield indirectly inherited Plugin classes.
    [descriptor for descriptor in plugins() if NamespacePlugin in descriptor.cls.__bases__],
    ids=lambda descriptor: descriptor.qualname,
)
def test_namespace_class_usage(descriptor: PluginDescriptor) -> None:
    """This test checks if :class:`NamespacePlugin` usage is correct.

    :class:`NamespacePlugin` is reserved for "grouping" other plugins of the same category. See for
    example :class:`BrowserPlugin` or :class:`WebserverPlugin`.

    If you want to expose plugin functions under a shared name, e.g. ``foo.bar`` and ``foo.baz``,
    you should use :class:`Plugin` with ``Plugin.__namespace__ = "foo"`` instead.

    References:
        - https://github.com/fox-it/dissect.target/issues/1180
    """

    assert descriptor.cls.__subclasses__(), (
        f"NamespacePlugin {descriptor.module}.{descriptor.qualname} has no subclasses, are you sure you're using NamespacePlugin correctly?"  # noqa: E501
    )
