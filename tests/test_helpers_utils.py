import pytest

from unittest.mock import mock_open
from pathlib import Path

from dissect.target.helpers.utils import readinto, slugify, parse_path_uri
from dissect.target.loader import LOADERS_BY_SCHEME


def test_slugify():
    assert slugify("foo/bar\\baz bla") == "foo_bar_baz_bla"


def test_filesystem_readinto():
    data = b"hello_world"
    mocked_file = mock_open(read_data=b"hello_world")

    buffer = bytearray([0] * 512)
    assert readinto(buffer, mocked_file.return_value) == len(data)
    assert buffer[: len(data)] == data
    assert len(buffer) == 512


@pytest.mark.parametrize(
    "path, expected",
    [
        # None objects fall through (BC)
        (None, (None, None, {}, "")),
        # Path objects fall through (BC/DRY)
        (Path("path"), (Path("path"), None, {}, "")),
        # local strings fall through (BC)
        ("local", (Path("local"), None, {}, "")),
        # basic path just gets boxed
        ("/path/to/file", (Path("/path/to/file"), None, {}, "")),
        ("C:\\path\\to\\file", (Path("C:\\path\\to\\file"), None, {}, "")),
        # selects correct loader
        ("tar://archive.tar.gz", (Path("archive.tar.gz"), LOADERS_BY_SCHEME["tar"], {}, "tar")),
        # works with absolute path
        ("tar:///root/archive.tar.gz", (Path("/root/archive.tar.gz"), LOADERS_BY_SCHEME["tar"], {}, "tar")),
        # file:// is same as nothing
        ("file:///root/archive.tar.gz", (Path("/root/archive.tar.gz"), None, {}, "file")),
        # non-existant scheme yields None value, so equals file://
        ("fake:///root/archive", (Path("/root/archive"), None, {}, "fake")),
        # can we extract query parameters?
        ("fake:///root/archive?a=1", (Path("/root/archive"), None, {"a": ["1"]}, "fake")),
        # invalid url
        ("fake:///?a=1", (Path("/"), None, {"a": ["1"]}, "fake")),
        ("fake://?a=1", (Path(""), None, {"a": ["1"]}, "fake")),
        # unparseable url, gets treated as path
        ("://?a=1", (Path(":/?a=1"), None, {"a": ["1"]}, "")),
        ("aaa.bbb", (Path("aaa.bbb"), None, {}, "")),
    ],
)
def test_parse_path_uri(path, expected):
    assert parse_path_uri(path) == expected
