from unittest.mock import mock_open

from dissect.target.helpers.utils import readinto, slugify


def test_slugify():
    assert slugify("foo/bar\\baz bla") == "foo_bar_baz_bla"


def test_filesystem_readinto():
    data = b"hello_world"
    mocked_file = mock_open(read_data=b"hello_world")

    buffer = bytearray([0] * 512)
    assert readinto(buffer, mocked_file.return_value) == len(data)
    assert buffer[: len(data)] == data
    assert len(buffer) == 512
