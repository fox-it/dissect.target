from io import StringIO

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
            "hello world\n  hello",
            {"hello": {"world": "hello"}},
        ),
        (
            "hello world\n  hello bye",
            {"hello": {"world": {"hello": "bye"}}},
        ),
        (
            "hello world\n  hello\nhello world\n  bye",
            {"hello": {"world": ["hello", "bye"]}},
        ),
    ],
)
def test_indented_parser(indented_string, expected_output) -> None:
    parsed_data = parse_data(Indentation, indented_string, seperator=(r"\s",))
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
