from __future__ import annotations

from unittest.mock import MagicMock, patch

from dissect.target import plugin
from dissect.target.plugins.general.loaders import LoaderListPlugin
from dissect.target.plugins.general.plugins import (
    PluginListPlugin,
    _categorize_functions,
    _generate_plugin_tree_overview,
)


def test_plugin_description() -> None:
    description = list(_generate_plugin_tree_overview({PluginListPlugin}, False))
    assert description == ["plugins - Print all available plugins. (output: no output)"]


def test_plugin_description_compacting() -> None:
    module = {"hello": {"world": {PluginListPlugin}}}

    description = list(_generate_plugin_tree_overview(module, False))
    assert description == [
        "hello:",
        "  world:",
        "    plugins - Print all available plugins. (output: no output)",
    ]


def test_plugin_description_in_dict_multiple() -> None:
    module = {"hello": {"world": {"data": {PluginListPlugin}, "data2": {PluginListPlugin}}}}

    description = list(_generate_plugin_tree_overview(module, False))
    assert description == [
        "hello:",
        "  world:",
        "    data:",
        "      plugins - Print all available plugins. (output: no output)",
        "    data2:",
        "      plugins - Print all available plugins. (output: no output)",
    ]


def test_plugin_description_multiple_in_path() -> None:
    module = {"hello": {"world": {PluginListPlugin, LoaderListPlugin}}}
    description = list(_generate_plugin_tree_overview(module, False))
    assert description == [
        "hello:",
        "  world:",
        "    loaders - List the available loaders. (output: no output)",
        "    plugins - Print all available plugins. (output: no output)",
    ]


@patch("dissect.target.plugins.general.plugins.plugin.load")
@patch("dissect.target.plugins.general.plugins.plugin.functions")
def test_categorize_plugins(mocked_plugins: MagicMock, mocked_load: MagicMock) -> None:
    mocked_plugins.return_value = [
        plugin.FunctionDescriptor(
            name="data",
            namespace=None,
            path="something.data",
            exported=True,
            internal=False,
            findable=True,
            alias=False,
            output=None,
            method_name="data",
            module="other.root.something.data",
            qualname="DataClass",
        ),
    ]
    assert _categorize_functions() == {"something": {mocked_load.return_value}}

    mocked_plugins.return_value = [
        plugin.FunctionDescriptor(
            name="data",
            namespace=None,
            path="something.data",
            exported=True,
            internal=False,
            findable=True,
            alias=False,
            output=None,
            method_name="data",
            module="other.root.something.data",
            qualname="DataClass1",
        ),
        plugin.FunctionDescriptor(
            name="data",
            namespace=None,
            path="something.data",
            exported=True,
            internal=False,
            findable=True,
            alias=False,
            output=None,
            method_name="data",
            module="other.root.something.data",
            qualname="DataClass2",
        ),
    ]
    assert _categorize_functions() == {"something": {mocked_load.return_value}}
