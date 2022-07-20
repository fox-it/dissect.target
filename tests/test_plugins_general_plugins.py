from unittest.mock import Mock, patch

import dissect.target.plugins.general.plugins as plugin
from dissect.target.plugins.general.plugins import (
    PluginListPlugin,
    categorize_plugins,
    dictify_module_recursive,
    output_plugin_description_recursive,
    update_dict_recursive,
)


def test_dictify_module():
    last_value = Mock()

    output_dict = dictify_module_recursive(["hello", "world"], last_value)

    assert output_dict == {"hello": {"world": last_value}}


def test_update_dict():
    tmp_dictionary = dict()

    update_dict_recursive(tmp_dictionary, dictify_module_recursive(["hello", "world"], None))
    update_dict_recursive(tmp_dictionary, dictify_module_recursive(["hello", "lawrence"], None))

    assert tmp_dictionary == {"hello": {"world": None, "lawrence": None}}


def test_plugin_description():
    description = [x for x in output_plugin_description_recursive(PluginListPlugin, False)]
    assert description == ["plugins - No documentation (output: no output)"]


def test_plugin_description_compacting():
    module = dictify_module_recursive(["hello", "world"], PluginListPlugin)

    description = [x for x in output_plugin_description_recursive(module, False)]
    assert description == [
        "hello:",
        "  world:",
        "    plugins - No documentation (output: no output)",
    ]


def test_plugin_description_in_dict_multiple():
    tmp_dictionary = dict()

    update_dict_recursive(tmp_dictionary, dictify_module_recursive(["hello", "world", "data"], PluginListPlugin))
    update_dict_recursive(tmp_dictionary, dictify_module_recursive(["hello", "world", "data2"], PluginListPlugin))

    description = [x for x in output_plugin_description_recursive(tmp_dictionary, False)]
    assert description == [
        "hello:",
        "  world:",
        "    data:",
        "      plugins - No documentation (output: no output)",
        "    data2:",
        "      plugins - No documentation (output: no output)",
    ]


@patch.object(plugin.plugin, "load")
@patch.object(plugin, "get_exported_plugins")
def test_categorize_plugins(mocked_export, mocked_load):
    mocked_export.return_value = [{"module": "something.data"}]
    assert categorize_plugins() == {"something": {"data": mocked_load.return_value}}
