from __future__ import annotations

import textwrap
from io import BytesIO, StringIO
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.configutil import (
    Bin,
    ConfigurationParser,
    CSVish,
    Default,
    Env,
    Indentation,
    Json,
    ScopeManager,
    SystemD,
    parse,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def parse_data(parser_type: type[ConfigurationParser], data_to_read: str, *args, **kwargs) -> dict:
    """Initializes parser_type as a parser which parses ``data_to_read``."""
    parser = parser_type(*args, **kwargs)
    parser.read_file(StringIO(data_to_read))
    return parser.parsed_data


@pytest.mark.parametrize(
    ("parser_string", "key", "value"),
    [
        ("hello world", "hello", "world"),
        ("hello world\t# new info", "hello", "world"),
    ],
)
def test_unknown_parser(parser_string: str, key: str, value: str) -> None:
    parsed_data = parse_data(Default, parser_string, separator=(r"\s",))
    assert parsed_data[key] == value


@pytest.mark.parametrize(
    ("parser_string", "separator", "expected_output"),
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
    ("comment_string", "comment_prefixes"),
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
    ("indented_string", "expected_output"),
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
            key value1
              key2 value2a
              key3 value3a
            key value1
              key2 value2b
              key3 value3b
            """,
            {"key value1": [{"key2": "value2a", "key3": "value3a"}, {"key2": "value2b", "key3": "value3b"}]},
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
    ("string_data", "expected_output"),
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


@pytest.mark.parametrize(
    ("data_string", "expected_data"),
    [
        (r'{"data" : "value"}', {"data": "value"}),
        (r'[{"data" : "value"}]', {"list_item0": {"data": "value"}}),
        (
            r'[{"data" : "value"}, {"data" : "value2"}]',
            {"list_item0": {"data": "value"}, "list_item1": {"data": "value2"}},
        ),
        (
            r'[{"data": [{"key1": "value1"}, {"key1": "value2"}]}]',
            {
                "list_item0": {
                    "data": {
                        "list_item0": {"key1": "value1"},
                        "list_item1": {"key1": "value2"},
                    },
                },
            },
        ),
    ],
)
def test_json_syntax(data_string: str, expected_data: dict | list) -> None:
    parser = Json()
    parser.parse_file(StringIO(data_string))

    assert parser.parsed_data == expected_data


@pytest.mark.parametrize(
    ("data", "expected_data"),
    [
        (b"\x00\x01\x02", {"binary": b"\x00\x01\x02", "size": "3"}),
    ],
)
def test_bin_parser(data: bytes, expected_data: dict) -> None:
    parser = Bin()
    parser.parse_file(BytesIO(data))
    assert parser.parsed_data == expected_data


@pytest.mark.parametrize(
    ("fields", "separator", "comment", "data_string", "expected_data"),
    [
        (["a", "b"], (r"\s+",), ("#",), "1 2", {"0": {"a": "1", "b": "2"}}),  # SSV
        (["a", "b"], (r"\s+",), ("#",), "1 2\n3 4", {"0": {"a": "1", "b": "2"}, "1": {"a": "3", "b": "4"}}),  # SSV-2
        (["a", "b"], (r"\s+",), ("#",), "1\t2", {"0": {"a": "1", "b": "2"}}),  # TSV
        (["a", "b"], (r",",), ("#",), "1,2", {"0": {"a": "1", "b": "2"}}),  # CSV
        (["a", "b"], (r"\|",), ("#",), "1|2", {"0": {"a": "1", "b": "2"}}),  # DSV
        (["a", "b"], (r"\|",), ("#",), "#9|9\n1|2", {"0": {"a": "1", "b": "2"}}),  # comments
        (["a", "b"], (r"\s+",), ("#",), "#9 9\n1 2 3", {"0": {"a": "1", "b": "2 3"}}),  # trailing column
        (["a", "b"], (r"\s+",), ("#",), "x", {"0": {"line": "x"}}),  # unparsed
    ],
)
def test_csv_syntax(
    fields: list[str], separator: tuple[str, ...], comment: tuple[str, ...], data_string: str, expected_data: dict
) -> None:
    parser = CSVish(fields=fields, separator=separator, comment_prefixes=comment)
    parser.parse_file(StringIO(data_string))
    assert parser.parsed_data == expected_data


def test_parse(target_linux: Target, fs_linux: VirtualFilesystem, tmp_path: Path) -> None:
    # File does not exist on the system in the first place
    with pytest.raises(FileNotFoundError):
        parse(target_linux.fs.path("/path/to/file"))

    file_path = tmp_path.joinpath("path/to/file")
    file_path.parent.mkdir(parents=True)
    file_path.touch()

    fs_linux.map_dir("/", tmp_path.absolute())

    # Trying to read a directory
    with pytest.raises(FileNotFoundError):
        parse(target_linux.fs.path("/path/to"))

    parse(target_linux.fs.path("/path/to/file"))


@pytest.mark.parametrize(
    ("input", "expected_output"),
    [
        ("", {}),
        ("foo=bar\n", {"foo": "bar"}),
        ("foo = bar \n", {"foo": "bar"}),
        ('foo = "bar"\n', {"foo": "bar"}),
        ("foo=bar\nempty=\nhello=world\n", {"foo": "bar", "empty": "", "hello": "world"}),
        # multiple delimiters
        ("foo=option=foo,value=bar", {"foo": "option=foo,value=bar"}),
        # types
        ("foo=123", {"foo": 123}),
        ("foo=1", {"foo": True}),
        ("foo=0", {"foo": False}),
        ("foo='1'", {"foo": True}),
        ("foo=true", {"foo": True}),
        ('foo="False"\nbar="true"\n', {"bar": True, "foo": False}),
        # comments
        ("foo=bar#\n", {"foo": "bar#"}),
        ('foo="bar#"\n', {"foo": "bar#"}),
        ("foo='bar#'\n", {"foo": "bar#"}),
        ("foo=bar # comment\n", {"foo": "bar"}),
        ("foo='bar' # comment\n", {"foo": "bar"}),
        ("foo='bar #' # comment\n", {"foo": "bar #"}),
        ("foo=bar# not a comment\n", {"foo": "bar# not a comment"}),
        ("foo='bar # not a comment'\n", {"foo": "bar # not a comment"}),
        (Path(absolute_path("_data/helpers/configutil/env")), {"foo": "'bar"}),
        # whitespaces inside quotes
        ("foo='bar '\n", {"foo": "bar "}),
        # quotes inside values
        ('foo=ba"r\n', {"foo": 'ba"r'}),
    ],
)
def test_env_parser(input: str | Path, expected_output: dict) -> None:
    parser = Env(comments=False)

    if isinstance(input, str):
        parser.parse_file(StringIO(input))
    else:
        parser.parse_file(input.open("r"))

    assert parser.parsed_data == expected_output
