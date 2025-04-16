from __future__ import annotations

import inspect
import itertools
import textwrap
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from dissect.target.plugin import Plugin

NO_DOCS = "No documentation"

FUNCTION_OUTPUT_DESCRIPTION = {
    "none": "no output",
    "default": "text",
    "record": "records",
    "yield": "lines",
}

INDENT_STEP = " " * 4

FUNC_DOC_TEMPLATE = "{func_name} - {short_description} (output: {output_type})"


def get_docstring(obj: Any, placeholder: str = NO_DOCS) -> str:
    """Get object's docstring or a placeholder if no docstring found."""
    # Use of `inspect.cleandoc()` is preferred to `textwrap.dedent()` here
    # because many multi-line docstrings in the codebase
    # have no indentation in the first line, which confuses `dedent()`
    return inspect.cleandoc(obj.__doc__) if obj.__doc__ else placeholder


def get_func_description(func: Callable, with_docstrings: bool = False) -> str:
    klass, func = _get_real_func_obj(func)
    func_output, func_doc = _get_func_details(func)

    # get user-friendly function name
    func_name = _get_full_func_name(klass, func)

    if with_docstrings:
        func_title = f"`{func_name}` (output: {func_output})"
        func_doc = textwrap.indent(func_doc, prefix=INDENT_STEP)
        desc = f"{func_title}\n\n{func_doc}"
    else:
        docstring_first_line = func_doc.splitlines()[0].lstrip()
        desc = FUNC_DOC_TEMPLATE.format(
            func_name=func_name, short_description=docstring_first_line, output_type=func_output
        )

    return desc


def get_plugin_functions_desc(plugin_class: type[Plugin], with_docstrings: bool = False) -> str:
    descriptions = []
    for func_name in plugin_class.__exports__:
        func_obj = getattr(plugin_class, func_name)
        if func_obj is getattr(plugin_class, "__call__", None):  # noqa: B004
            continue

        _, func = _get_real_func_obj(func_obj)
        func_desc = get_func_description(func, with_docstrings=with_docstrings)
        descriptions.append(func_desc)

    # sort functions in the plugin alphabetically
    descriptions = sorted(descriptions)

    if with_docstrings:
        # add empty lines after every func description
        descriptions = [block for pair in zip(descriptions, itertools.repeat("")) for block in pair]

    return "\n".join(descriptions)


def get_plugin_description(plugin_class: type[Plugin]) -> str:
    plugin_name = plugin_class.__name__
    plugin_desc_title = f"`{plugin_name}` (`{plugin_class.__module__}.{plugin_name}`)"
    plugin_doc = textwrap.indent(get_docstring(plugin_class), prefix=INDENT_STEP)
    return f"{plugin_desc_title}\n\n{plugin_doc}"


def get_plugin_overview(
    plugin_class: type[Plugin], with_plugin_desc: bool = False, with_func_docstrings: bool = False
) -> str:
    paragraphs = []

    if with_plugin_desc:
        plugin_desc = get_plugin_description(plugin_class)
        paragraphs.append(plugin_desc)

        # Add a line break between plugin description and function descriptions
        paragraphs.append("")

    func_descriptions_paragraph = get_plugin_functions_desc(plugin_class, with_docstrings=with_func_docstrings)

    # Indent func docs additionally if plugin desc is printed
    if with_plugin_desc:
        func_descriptions_paragraph = textwrap.indent(
            func_descriptions_paragraph,
            prefix=INDENT_STEP,
        )

    paragraphs.append(func_descriptions_paragraph)
    return "\n".join(paragraphs)


def _get_plugin_class_for_func(func: Callable) -> type[Plugin]:
    """Return plugin class for provided function instance."""
    func_parent_name = func.__qualname__.rsplit(".", 1)[0]
    return getattr(inspect.getmodule(func), func_parent_name, None)


def _get_real_func_obj(func: Callable) -> tuple[type[Plugin], Callable]:
    """Return a tuple with plugin class and underlying function object for provided function instance."""
    klass = None

    if isinstance(func, property):
        # turn property into function
        func = func.fget

    if inspect.ismethod(func):
        for klass in inspect.getmro(func.__self__.__class__):
            if func.__name__ in klass.__dict__:
                break
        else:
            func = getattr(func, "__func__", func)

    if inspect.isfunction(func):
        klass = _get_plugin_class_for_func(func)

    if not klass:
        raise ValueError(f"Can't find class for {func}")

    return (klass, func)


def _get_func_details(func: Callable) -> tuple[str, str]:
    """Return a tuple with function's name, output label and docstring."""
    func_doc = get_docstring(func)

    if hasattr(func, "__output__") and func.__output__ in FUNCTION_OUTPUT_DESCRIPTION:
        func_output = FUNCTION_OUTPUT_DESCRIPTION[func.__output__]
    else:
        func_output = "unknown"

    return (func_output, func_doc)


def _get_full_func_name(plugin_class: type[Plugin], func: Callable) -> str:
    func_name = func.__name__

    if hasattr(plugin_class, "__namespace__") and plugin_class.__namespace__:
        func_name = f"{plugin_class.__namespace__}.{func_name}"

    return func_name
