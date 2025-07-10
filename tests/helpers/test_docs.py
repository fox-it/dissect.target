from __future__ import annotations

from dissect.target.helpers import docs
from dissect.target.plugins.apps.webserver.iis import IISLogsPlugin


def get_nonempty_lines_set(paragraph: str) -> set[str]:
    return set(filter(None, (line.strip() for line in paragraph.splitlines())))


def test_docs_plugin_description() -> None:
    plugin_desc = docs.get_plugin_description(IISLogsPlugin)

    assert plugin_desc
    assert IISLogsPlugin.__name__ in plugin_desc

    assert get_nonempty_lines_set(IISLogsPlugin.__doc__).issubset(get_nonempty_lines_set(plugin_desc))


def test_docs_plugin_functions_desc() -> None:
    functions_short_desc = docs.get_plugin_functions_desc(IISLogsPlugin, with_docstrings=False)

    assert functions_short_desc
    desc_lines = functions_short_desc.splitlines()

    assert len(desc_lines) == 2
    assert "iis.logs" in functions_short_desc
    assert "Return contents of IIS (v7 and above) log files." in functions_short_desc
    assert "output: records" in functions_short_desc

    functions_long_desc = docs.get_plugin_functions_desc(IISLogsPlugin, with_docstrings=True)

    assert functions_long_desc

    lines_bag = get_nonempty_lines_set(functions_long_desc)

    assert "Return contents of IIS (v7 and above) log files." in lines_bag
    assert "Supported log formats: IIS, W3C." in lines_bag


def test_docs_get_func_description() -> None:
    func = IISLogsPlugin.logs
    func_desc = docs.get_func_description(func, with_docstrings=False)

    assert func_desc == "iis.logs - Return contents of IIS (v7 and above) log files. (output: records)"

    func_desc = docs.get_func_description(func, with_docstrings=True)
    lines_bag = get_nonempty_lines_set(func_desc)

    assert "Return contents of IIS (v7 and above) log files." in lines_bag
    assert "Supported log formats: IIS, W3C." in lines_bag
