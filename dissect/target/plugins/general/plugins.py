from __future__ import annotations

import textwrap

from dissect.target import plugin
from dissect.target.helpers.docs import INDENT_STEP, get_plugin_overview
from dissect.target.plugin import Plugin, arg, export


def generate_function_overview(
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
        "\n".join(failed_descriptions) if failed_descriptions else "None",
        prefix=INDENT_STEP,
    )

    lines = [
        "Available plugins:",
        plugins_list,
        "",
        "Failed to load:",
        failed_list,
        "",
    ]
    return "\n".join(lines)


def _categorize_functions(functions: list[plugin.FunctionDescriptor] | None = None) -> dict:
    """Categorize functions based on its module path."""

    functions = functions or [f for f in plugin.functions() if f.exported]
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
    def check_compatible(self) -> None:
        pass

    @export(output="none", cache=False)
    @arg("--docs", dest="print_docs", action="store_true")
    def plugins(self, print_docs: bool = False) -> None:
        overview = generate_function_overview(include_docs=print_docs)
        print(overview)
