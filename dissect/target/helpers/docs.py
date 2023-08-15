import inspect
import itertools
import textwrap
from typing import Any, Callable, Tuple, Type

NO_DOCS = "No documentation"

FUNCTION_OUTPUT_DESCRIPTION = {
    "none": "no output",
    "default": "text",
    "record": "records",
    "yield": "lines",
}

INDENT_STEP = " " * 4


def get_plugin_class_for_func(func: Callable) -> Type:
    """Return pluging class for provided function instance"""
    func_parent_name = func.__qualname__.rsplit(".", 1)[0]
    klass = getattr(inspect.getmodule(func), func_parent_name, None)
    return klass


def get_real_func_obj(func: Callable) -> Tuple[Type, Callable]:
    """Return a tuple with plugin class and underlying func object for provided function instance"""
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
        klass = get_plugin_class_for_func(func)

    if not klass:
        raise ValueError(f"Can't find class for {func}")

    return (klass, func)


def get_docstring(obj: Any, placeholder=NO_DOCS) -> str:
    """Get object's docstring or a placeholder if no docstring found"""
    # Use of `inspect.cleandoc()` is preferred to `textwrap.dedent()` here
    # because many multi-line docstrings in the codebase
    # have no indentation in the first line, which confuses `dedent()`
    return inspect.cleandoc(obj.__doc__) if obj.__doc__ else placeholder


def get_func_details(func: Callable) -> Tuple[str, str]:
    """Return a tuple with function's name, output label and docstring"""
    func_doc = get_docstring(func)

    if hasattr(func, "__output__") and func.__output__ in FUNCTION_OUTPUT_DESCRIPTION:
        func_output = FUNCTION_OUTPUT_DESCRIPTION[func.__output__]
    else:
        func_output = "unknown"

    return (func_output, func_doc)


def get_full_func_name(plugin_class: Type, func: Callable) -> str:
    func_name = func.__name__

    if hasattr(plugin_class, "__namespace__") and plugin_class.__namespace__:
        func_name = f"{plugin_class.__namespace__}.{func_name}"

    return func_name


FUNC_DOC_TEMPLATE = "{func_name} - {short_description} (output: {output_type})"


def get_func_description(func: Callable, with_docstrings: bool = False) -> str:
    klass, func = get_real_func_obj(func)
    func_output, func_doc = get_func_details(func)

    # get user-friendly function name
    func_name = get_full_func_name(klass, func)

    if with_docstrings:
        func_title = f"`{func_name}` (output: {func_output})"
        func_doc = textwrap.indent(func_doc, prefix=INDENT_STEP)
        desc = "\n".join([func_title, "", func_doc])
    else:
        docstring_first_line = func_doc.splitlines()[0].lstrip()
        desc = FUNC_DOC_TEMPLATE.format(
            func_name=func_name, short_description=docstring_first_line, output_type=func_output
        )

    return desc


def get_plugin_functions_desc(plugin_class: Type, with_docstrings: bool = False) -> str:
    descriptions = []
    for func_name in plugin_class.__exports__:
        func_obj = getattr(plugin_class, func_name)
        if getattr(func_obj, "get_func_doc_spec", None):
            func_desc = FUNC_DOC_TEMPLATE.format_map(func_obj.get_func_doc_spec())
        else:
            _, func = get_real_func_obj(func_obj)
            func_desc = get_func_description(func, with_docstrings=with_docstrings)
        descriptions.append(func_desc)

    # sort functions in the plugin alphabetically
    descriptions = sorted(descriptions)

    if with_docstrings:
        # add empty lines after every func description
        descriptions = [block for pair in zip(descriptions, itertools.repeat("")) for block in pair]

    paragraph = "\n".join(descriptions)
    return paragraph


def get_plugin_description(plugin_class: Type) -> str:
    plugin_name = plugin_class.__name__
    plugin_desc_title = f"`{plugin_name}` (`{plugin_class.__module__}.{plugin_name}`)"
    plugin_doc = textwrap.indent(get_docstring(plugin_class), prefix=INDENT_STEP)
    paragraph = "\n".join([plugin_desc_title, "", plugin_doc])
    return paragraph


def get_plugin_overview(plugin_class: Type, with_plugin_desc: bool = False, with_func_docstrings: bool = False) -> str:
    paragraphs = []

    if with_plugin_desc:
        plugin_desc = get_plugin_description(plugin_class)
        paragraphs.append(plugin_desc)

        # add a line break between plugin description and function descriptions
        paragraphs.append("")

    func_descriptions_paragraph = get_plugin_functions_desc(plugin_class, with_docstrings=with_func_docstrings)

    # indent func docs additionally if plugin desc is printed
    if with_plugin_desc:
        func_descriptions_paragraph = textwrap.indent(
            func_descriptions_paragraph,
            prefix=INDENT_STEP,
        )

    paragraphs.append(func_descriptions_paragraph)
    overview = "\n".join(paragraphs)
    return overview
