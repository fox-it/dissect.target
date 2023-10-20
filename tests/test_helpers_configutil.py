from io import StringIO
import textwrap
import pytest

from dissect.target.helpers.configutil import (
    ConfigurationParser,
    Default,
    Indentation,
)


def parse_data(parser_type: type[ConfigurationParser], data_to_read: str, *args, **kwargs):
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
    parsed_data = parse_data(Default, parser_string, seperator=(r"\s",))
    assert parsed_data[key] == value


@pytest.mark.parametrize(
    "parser_string, seperator, expected_output",
    [
        ("hello=world", "=", {"hello": "world"}),
        ("hello = world", "=", {"hello": "world"}),
        ("hello=world", r"\s", {"hello=world": ""}),
        ("hello-world;20", ";", {"hello-world": "20"}),
        ("hello-world;20;20;20;20", ";", {"hello-world": "20;20;20;20"}),
    ],
)
def test_custom_seperators(parser_string: str, seperator: tuple, expected_output) -> None:
    parsed_data = parse_data(Default, parser_string, seperator=seperator, comment_prefixes=("#",))
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
        Default, f"hello world {comment_string}", seperator=(r"\s",), comment_prefixes=comment_prefixes
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
def test_indented_parser(indented_string, expected_output) -> None:
    parsed_data = parse_data(Indentation, textwrap.dedent(indented_string), seperator=(r"\s",))
    assert parsed_data == expected_output


def test_collapse_inversion():
    input_data = "hello world\nhello test\nworld world\nworld test"
    assert parse_data(
        Default,
        input_data,
        seperator=(r"\s",),
        collapse={"hello"},
        collapse_inverse=True,
    ) == {"hello": ["world", "test"], "world": "test"}


def test_change_scope():
    parser = Indentation(seperator=(r"\s",))
    current = {}

    # Scoping does not change
    new_current = parser._change_scope("key value", "key2 value2", "key", current)
    assert id(current) == id(new_current)

    # Scoping changes once
    new_current = parser._change_scope("key value", "  value2", "key", current)
    assert id(current) != id(new_current)
    assert current == {"key": {}}

    # Check if pop works as intended
    old_current = parser._change_scope("  value2", "test_line", "", new_current)
    assert id(current) == id(old_current)
