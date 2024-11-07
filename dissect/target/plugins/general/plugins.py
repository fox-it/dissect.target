from __future__ import annotations

import json
import textwrap
from typing import Iterator, Type

from dissect.target import plugin
from dissect.target.helpers.docs import INDENT_STEP, get_plugin_overview
from dissect.target.plugin import Plugin, arg, export


def categorize_plugins(plugins_selection: list[dict] = None) -> dict:
    """Categorize plugins based on the module it's from."""

    output_dict = dict()

    plugins_selection = plugins_selection or get_exported_plugins()

    for plugin_dict in plugins_selection:
        tmp_dict = dictify_module_recursive(
            list_of_items=plugin_dict["module"].split("."),
            last_value=plugin.load(plugin_dict),
        )
        update_dict_recursive(output_dict, tmp_dict)

    return output_dict


def get_exported_plugins() -> list:
    """Returns list of exported plugins."""
    return [p for p in plugin.plugins() if len(p["exports"])]


def dictify_module_recursive(list_of_items: list, last_value: Plugin) -> dict:
    """Create a dict from a list of strings.

    The last element inside the list, will point to `last_value`
    """
    if len(list_of_items) == 1:
        return {list_of_items[0]: last_value}
    else:
        return {list_of_items[0]: dictify_module_recursive(list_of_items[1:], last_value)}


def update_dict_recursive(source_dict: dict, updated_dict: dict) -> dict:
    """Update source dictionary with data in updated_dict."""

    for key, value in updated_dict.items():
        if isinstance(value, dict):
            source_dict[key] = update_dict_recursive(source_dict.get(key, {}), value)
        else:
            source_dict[key] = value
    return dict(sorted(source_dict.items()))


def output_plugin_description_recursive(
    structure_dict: dict | Plugin,
    print_docs: bool,
    indentation_step: int = 0,
) -> list[str]:
    """Create plugin overview with identations."""

    if isinstance(structure_dict, type) and issubclass(structure_dict, Plugin):
        return [get_plugin_description(structure_dict, print_docs, indentation_step)]

    return get_description_dict(structure_dict, print_docs, indentation_step)


def get_plugin_description(
    plugin_class: Type[Plugin],
    print_docs: bool,
    indentation_step: int,
) -> str:
    """Returns plugin_overview with specific indentation."""

    plugin_overview = get_plugin_overview(
        plugin_class=plugin_class,
        with_func_docstrings=print_docs,
        with_plugin_desc=print_docs,
    )
    return textwrap.indent(plugin_overview, prefix=" " * indentation_step)


def get_description_dict(
    structure_dict: dict,
    print_docs: bool,
    indentation_step: int,
) -> list[str]:
    """Returns a list of indented descriptions."""

    output_descriptions = []
    for key in structure_dict.keys():
        output_descriptions += [
            textwrap.indent(key + ":", prefix=" " * indentation_step) if key != "" else "OS plugins"
        ] + output_plugin_description_recursive(
            structure_dict[key],
            print_docs,
            indentation_step=indentation_step + 2,
        )

    return output_descriptions


class PluginListPlugin(Plugin):
    """Plugin list plugin (so meta)."""

    def check_compatible(self) -> None:
        pass

    @export(output="none", cache=False)
    @arg("--docs", dest="print_docs", action="store_true")
    # NOTE: We would prefer to re-use arguments across plugins from argparse in query.py, but that is not possible yet.
    # For now we use --as-json, but in the future this should be changed to inherit --json from target-query.
    # https://github.com/fox-it/dissect.target/pull/841
    # https://github.com/fox-it/dissect.target/issues/889
    @arg("--as-json", dest="as_json", action="store_true")
    def plugins(self, plugins: list[Plugin] = None, print_docs: bool = False, as_json: bool = False) -> None:
        """Print all available plugins."""

        dict_plugins = list({p.path: p.plugin_desc for p in plugins}.values())
        categorized_plugins = dict(sorted(categorize_plugins(dict_plugins).items()))

        plugin_descriptions = output_plugin_description_recursive(categorized_plugins, print_docs)

        plugins_list = textwrap.indent(
            "\n".join(plugin_descriptions) if plugin_descriptions else "None",
            prefix=INDENT_STEP,
        )

        failed_descriptions = []
        failed_items = plugin.failed()
        for failed_item in failed_items:
            module = failed_item["module"]
            exception = failed_item["stacktrace"][-1].rstrip()
            failed_descriptions.append(
                textwrap.dedent(
                    f"""\
                        Module: {module}
                        Reason: {exception}
                    """
                )
            )

        failed_list = textwrap.indent(
            "\n".join(failed_descriptions) if failed_descriptions else "None",
            prefix=INDENT_STEP,
        )

        output_lines = [
            "Available plugins:",
            plugins_list,
            "",
            "Failed to load:",
            failed_list,
        ]

        if as_json:
            out = {"loaded": list(generate_plugins_json(plugins))}

            if failed_plugins := plugin.failed():
                out["failed"] = [
                    {"module": p["module"], "stacktrace": "".join(p["stacktrace"])} for p in failed_plugins
                ]

            print(json.dumps(out), end="")

        else:
            print("\n".join(output_lines))


def generate_plugins_json(plugins: list[Plugin]) -> Iterator[dict]:
    """Generates JSON output of a list of :class:`Plugin`s."""

    for p in plugins:
        func = getattr(p.class_object, p.method_name)
        description = getattr(func, "__doc__", None)
        summary = description.split("\n\n", 1)[0].strip() if description else None

        yield {
            "name": p.name,
            "output": p.output_type,
            "description": summary,
            "path": p.path,
        }
