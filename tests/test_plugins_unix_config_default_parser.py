from io import StringIO

from dissect.target.plugins.os.unix.config import (
    Default,
)

import pytest


@pytest.mark.parametrize(
    "parser_string, key, value",
    [
        ("hello world", "hello", "world"),
        ("hello world\t# new info", "hello", "world"),
    ],
)
def test_unknown_parser(parser_string: str, key: str, value: str):
    parser = Default(None)
    parser.read_file(StringIO(parser_string))
    assert parser.parsed_data[key] == value


@pytest.mark.parametrize(
    "parser_string, seperator, expected_output",
    [
        ("hello=world", "=", {"hello": "world"}),
        ("hello = world", "=", {"hello": "world"}),
        ("hello=world", r"\s", {"hello=world": ""}),
        ("hello-world;20", ";", {"hello-world": "20"}),
        ("hello-world;20;20;20;20", ";", {"hello-world": "20 20 20 20"}),
    ],
)
def test_custom_seperators(parser_string: str, seperator: tuple, expected_output):
    parser = Default(None, seperator, comment_prefixes=("#",))
    parser.read_file(StringIO(parser_string))
    assert parser.parsed_data == expected_output


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
def test_custom_comments(comment_string: str, comment_prefixes: str):
    parser = Default(None, seperator=r"\s", comment_prefixes=comment_prefixes)
    parser_string = StringIO(f"hello world {comment_string}")
    parser.read_file(parser_string)
    assert parser.parsed_data == {"hello": "world"}
