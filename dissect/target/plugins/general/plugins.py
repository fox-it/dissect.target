from __future__ import annotations

import json
import textwrap

from dissect.target import plugin
from dissect.target.helpers.docs import INDENT_STEP, get_plugin_overview
from dissect.target.plugin import Plugin, arg, export
from dissect.target.plugins.os.default._os import DefaultPlugin


def generate_functions_overview(
    functions: list[plugin.FunctionDescriptor] | None = None, include_docs: bool = False
) -> list[str]:
    """Generate a tree list of functions with optional documentation."""

    categorized_plugins = _categorize_functions(functions)
    plugin_descriptions = _generate_plugin_tree_overview(categorized_plugins, include_docs)

    plugins_list = textwrap.indent(
        "\n".join(plugin_descriptions) if plugin_descriptions else "None",
        prefix=INDENT_STEP,
    )

    failed_descriptions = []
    failed_items = plugin.failed()
    for failed_item in failed_items:
        module = failed_item.module
        exception = failed_item.stacktrace[-1].rstrip()
        failed_descriptions.append(
            textwrap.dedent(
                f"""\
                    Module: {module}
                    Reason: {exception}
                """
            )
        )

    failed_list = textwrap.indent(
        "\n".join(failed_descriptions) if failed_descriptions else "None\n",
        prefix=INDENT_STEP,
    )

    lines = [
        "Available plugins:",
        plugins_list,
        "",
        "Failed to load:",
        failed_list,
    ]
    return "\n".join(lines)


def generate_functions_json(functions: list[plugin.FunctionDescriptor] | None = None) -> str:
    """Generate a JSON representation of all available functions."""

    loaded = []
    failed = []

    for desc in functions or _get_default_functions():
        plugincls = plugin.load(desc)
        func = getattr(plugincls, desc.method_name)
        docstring = func.__doc__.split("\n\n", 1)[0].strip() if func.__doc__ else None
        arguments = [
            {
                "name": name[0],
                "type": getattr(arg.get("type"), "__name__", None),
                "help": arg.get("help"),
                "default": arg.get("default"),
            }
            for name, arg in getattr(func, "__args__", [])
        ]

        loaded.append(
            {
                "name": desc.name,
                "output": desc.output,
                "description": docstring,
                "arguments": arguments,
                "path": desc.path,
            }
        )

    if failures := plugin.failed():
        failed = [{"module": f.module, "stacktrace": "".join(f.stacktrace)} for f in failures]

    return json.dumps({"loaded": loaded, "failed": failed})


def _get_default_functions() -> list[plugin.FunctionDescriptor]:
    return [f for f in plugin.functions() if f.exported] + [
        f for f in plugin.functions(index="__os__") if f.exported and f.module == DefaultPlugin.__module__
    ]


def _categorize_functions(functions: list[plugin.FunctionDescriptor] | None = None) -> dict:
    """Categorize functions based on its module path."""

    functions = functions or _get_default_functions()
    result = {}

    for desc in functions:
        obj = result
        parts = desc.path.split(".")

        if not desc.namespace or (desc.namespace and desc.method_name != "__call__"):
            parts = parts[:-1]

        for part in parts[:-1]:
            obj = obj.setdefault(part, {})

        if parts[-1] not in obj:
            obj[parts[-1]] = plugin.load(desc)

    return dict(sorted(result.items()))


def _generate_plugin_tree_overview(
    plugin_tree: dict | type[Plugin],
    print_docs: bool,
    indent: int = 0,
) -> list[str]:
    """Create plugin overview with identations."""

    if isinstance(plugin_tree, type) and issubclass(plugin_tree, Plugin):
        return [
            textwrap.indent(
                get_plugin_overview(plugin_tree, print_docs, print_docs),
                prefix=" " * indent,
            )
        ]

    result = []
    for key in plugin_tree.keys():
        result.append(textwrap.indent(key + ":", prefix=" " * indent) if key != "" else "OS plugins")
        result.extend(
            _generate_plugin_tree_overview(
                plugin_tree[key],
                print_docs,
                indent=indent + 2,
            )
        )

    return result


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
    def plugins(self, print_docs: bool = False, as_json: bool = False) -> None:
        """Print all available plugins."""
        if as_json:
            print(generate_functions_json(), end="")
        else:
            print(generate_functions_overview(include_docs=print_docs))
