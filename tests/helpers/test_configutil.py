import textwrap
from io import StringIO
from pathlib import Path

import pytest

from dissect.target.helpers.configutil import (
    ConfigurationParser,
    Default,
    Indentation,
    ScopeManager,
    SystemD,
)
from tests._utils import absolute_path


def parse_data(parser_type: type[ConfigurationParser], data_to_read: str, *args, **kwargs) -> dict:
    """Initializes parser_type as a parser which parses ``data_to_read``"""
    parser = parser_type(*args, **kwargs)
    parser.read_file(StringIO(data_to_read))
    return parser.parsed_data


@pytest.mark.parametrize(
    "parser_string, key, value",
    [
        ("hello world", "hello", "world"),
        ("hello world\t# new info", "hello", "world"),
    ],
)
def test_unknown_parser(parser_string: str, key: str, value: str) -> None:
    parsed_data = parse_data(Default, parser_string, separator=(r"\s",))
    assert parsed_data[key] == value


@pytest.mark.parametrize(
    "parser_string, separator, expected_output",
    [
        ("hello=world", "=", {"hello": "world"}),
        ("hello = world", "=", {"hello": "world"}),
        ("hello=world", r"\s", {"hello=world": ""}),
        ("hello-world;20", ";", {"hello-world": "20"}),
        ("hello-world;20;20;20;20", ";", {"hello-world": "20;20;20;20"}),
    ],
)
def test_custom_separators(parser_string: str, separator: tuple, expected_output: dict[str, str]) -> None:
    parsed_data = parse_data(Default, parser_string, separator=separator, comment_prefixes=("#",))
    assert parsed_data == expected_output


@pytest.mark.parametrize(
    "comment_string, comment_prefixes",
    [
        ("; some information", (";", "#")),
        ("# Some other info", (";", "#")),
        ("# Comment ; another comment", (";", "#")),
        ("// code comment", ("//",)),
        (";20;20;20;20", (";",)),
    ],
)
def test_custom_comments(comment_string: str, comment_prefixes: tuple[str, ...]) -> None:
    parsed_data = parse_data(
        Default, f"hello world {comment_string}", separator=(r"\s",), comment_prefixes=comment_prefixes
    )
    assert parsed_data == {"hello": "world"}


@pytest.mark.parametrize(
    "indented_string, expected_output",
    [
        (
            """
            key value1
              value2
            """,
            {"key value1": "value2"},
        ),
        (
            """
            key1 value1
              key2 value2
            """,
            {"key1 value1": {"key2": "value2"}},
        ),
        (
            """
            key value1
              value2
            key value1
              value3
            """,
            {"key value1": ["value2", "value3"]},
        ),
        (
            """
            key value
              key2 value2
              key3 value3

            key value4
              key2 value2
            """,
            {"key value": {"key2": "value2", "key3": "value3"}, "key value4": {"key2": "value2"}},
        ),
        (
            """
            key value
                key2 value2
                key3 value3

            key value4
                key2
            """,
            {"key value": {"key2": "value2", "key3": "value3"}, "key value4": "key2"},
        ),
        (
            """
            key value
                value2
            key2 value
                key3 value3
            """,
            {"key value": "value2", "key2 value": {"key3": "value3"}},
        ),
    ],
)
def test_indented_parser(indented_string: str, expected_output: dict[str, dict]) -> None:
    parsed_data = parse_data(Indentation, textwrap.dedent(indented_string), separator=(r"\s",))
    assert parsed_data == expected_output


def test_collapse_inversion() -> None:
    input_data = "hello world\nhello test\nworld world\nworld test"
    assert parse_data(
        Default,
        input_data,
        separator=(r"\s",),
        collapse={"hello"},
        collapse_inverse=True,
    ) == {"hello": ["world", "test"], "world": "test"}


def test_change_scope() -> None:
    parser = Indentation(separator=(r"\s",))
    manager = ScopeManager()

    # Scoping does not change
    changed = parser._change_scope(manager, line="key value", next_line="key2 value2", key="key value")
    assert id(manager._root) == id(manager._current)
    assert not changed
    old_current = manager._current

    # Scoping changes once
    changed = parser._change_scope(manager, line="key2 value2", next_line="  value2", key="key2 value2")
    assert id(old_current) != id(manager._current)
    assert changed
    assert manager._root == {"key2 value2": {}}
    old_current = manager._current

    # If the current line still contains empty space, return the same scope
    changed = parser._change_scope(manager, line="  value2", next_line="test_line", key="value2")
    assert id(old_current) == id(manager._current)
    assert not changed

    changed = parser._change_scope(manager, line="test data", next_line=None, key="test data")
    assert id(old_current) == id(manager._current)
    assert not changed


@pytest.mark.parametrize(
    "string_data, expected_output",
    [
        ("[Unit]\n[System]\n", {"Unit": {}, "System": {}}),
        ("[Unit]\nkey=value;\n[System]", {"Unit": {"key": "value;"}, "System": {}}),
        (
            "[Unit]\nkey=value \\\n continued\\\nvalue\nkey2=value2",
            {
                "Unit": {
                    "key": "value continued value",
                    "key2": "value2",
                }
            },
        ),
        (
            "[Unit]\nkey=value \\\n continued\\\n[System]",
            {
                "Unit": {
                    "key": "value continued",
                },
                "System": {},
            },
        ),
        (
            "[Unit]\nnew_lines=hello \\\nworld\\\ntest\\\n help",
            {
                "Unit": {"new_lines": "hello world test help"},
            },
        ),
    ],
    ids=["scoping changes", "key value extraction", "line continuation", "faulty configuration", "weird indentation"],
)
def test_systemd_scope(string_data: str, expected_output: dict) -> None:
    parser = SystemD()

    parser.parse_file(StringIO(string_data))

    assert parser.parsed_data == expected_output


def test_systemd_basic_syntax() -> None:
    data = Path(absolute_path("_data/helpers/configutil/systemd.syntax"))
    output = {
        "Section A": {
            "KeyOne": "value 1",
            "KeyTwo": "value 2",
        },
        "Section B": {
            "Setting": '"something" "some thing" "..."',
            "KeyTwo": "value 2 value 2 continued",
        },
        "Section C": {
            "KeyThree": "value 3 value 3 continued",
        },
    }

    parser = SystemD()
    parser.parse_file(StringIO(data.read_text()))

    assert parser.parsed_data == output
