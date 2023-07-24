#!/bin/python3
from unittest.mock import Mock, patch

import pytest
from flow.record.fieldtypes import uri

import dissect.target.helpers.hashutil as hashutil
from dissect.target.exceptions import FileNotFoundError, IsADirectoryError


def create_mocked_windows_target():
    mocked_target = Mock()
    mocked_target.os = "windows"
    mocked_target.fs.hash = hashutil.common
    return mocked_target


@patch("dissect.target.helpers.hashutil.ResolverPlugin.resolve")
def test_hash_uri(resolver):
    """Determine hash functions"""

    target = create_mocked_windows_target()
    test_file = open(__file__, "rb")
    resolver.return_value = test_file
    output = hashutil.hash_uri(target, __file__)
    assert output[0].name == __file__
    assert len(output[1][0]) == 32
    assert len(output[1][1]) == 40
    assert len(output[1][2]) == 64


@patch("dissect.target.helpers.hashutil.ResolverPlugin.resolve")
def test_hash_uri_none(resolver):
    """Determine hash functions"""
    with pytest.raises(FileNotFoundError):
        hashutil.hash_uri(Mock(), None)


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ({"name": uri}, 1),
        ({"name": uri, "test": uri}, 2),
        ({"name": uri, "test": str}, 1),
    ],
)
@patch("flow.record.Record")
def test_record_with_uris(record, test_input, expected):
    record._desc.name = "test"
    record._field_types = test_input
    with patch("dissect.target.helpers.hashutil.hash_uri", return_value=("test", None)):
        hashed_uris = hashutil.hash_uri_records(Mock(), record)
        assert hashed_uris.name == "test"
        assert len(hashed_uris.records) == 2
        assert hashed_uris.records[0] == record
        assert len(hashed_uris.records[1].paths) == expected
        assert len(hashed_uris.records[1].digests) == expected


@pytest.mark.parametrize(
    "test_input",
    [
        ({}),
        ({"name": str}),
        ({"name": str, "test": str}),
    ],
)
@patch("flow.record.Record")
def test_record_without_uris(record, test_input):
    with patch("dissect.target.helpers.hashutil.hash_uri"):
        assert hashutil.hash_uri_records(Mock(), record) == record


@pytest.mark.parametrize(
    "side_effects,expected",
    [
        ([FileNotFoundError], 0),
        ([IsADirectoryError], 0),
        ([FileNotFoundError, FileNotFoundError], 0),
        ([IsADirectoryError, IsADirectoryError], 0),
        ([FileNotFoundError, IsADirectoryError], 0),
        ([FileNotFoundError, ("test", None)], 1),
        ([IsADirectoryError, ("test", None)], 1),
        ([FileNotFoundError, ("test", None), IsADirectoryError], 1),
        ([("test", None), FileNotFoundError, ("test", None)], 2),
        ([("test", None), IsADirectoryError, ("test", None)], 2),
    ],
)
@patch("dissect.target.helpers.hashutil.hash_uri")
def test_uris_with_exception(hash_uri, side_effects, expected):
    hash_uri.side_effect = side_effects
    with patch("flow.record.Record") as record:
        # Create a list of uris with the size of the record
        record._desc.name = "test"
        record._field_types = {str(i): uri for i in range(len(side_effects))}
        hashed_record = hashutil.hash_uri_records(Mock(), record)

        if not expected:
            assert hashed_record == record
        else:
            assert len(hashed_record.records[1].paths) == expected
            assert hashed_record.records[1].paths == ["test"] * expected
            assert len(hashed_record.records[1].digests) == expected
