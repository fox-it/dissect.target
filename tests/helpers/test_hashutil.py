from typing import Union
from unittest.mock import Mock, patch

import pytest
from flow.record import Record
from flow.record.fieldtypes import path

import dissect.target.helpers.hashutil as hashutil
from dissect.target.exceptions import FileNotFoundError, IsADirectoryError

HASHES = ("CAFEF00D" * 4, "F4CEF001" * 5, "DEADBEEF" * 8)


@pytest.fixture
def mock_target() -> Mock:
    target = Mock()
    target.os = "windows"
    target.fs.hash = lambda path: HASHES
    target.resolve = lambda path: path
    return target


def resolve_func(path: str) -> str:
    return f"/resolved{path}"


def test_common() -> None:
    fh = open(__file__, "rb")
    output = hashutil.common(fh)

    assert len(output[0]) == 32
    assert len(output[1]) == 40
    assert len(output[2]) == 64


def test_hash_uri_records() -> None:
    with pytest.deprecated_call():
        with patch("dissect.target.helpers.hashutil.hash_path_records", autospec=True) as hash_path_records:
            target = Mock()
            record = Mock()
            hashutil.hash_uri_records(target, record)
            hash_path_records.assert_called_with(target, record)


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ({"name": path}, 1),
        ({"name": path, "test": path}, 2),
        ({"name": path, "test": str}, 1),
    ],
)
@patch("flow.record.Record")
def test_hash_path_records_with_paths(
    record: Record,
    mock_target: Mock,
    test_input: dict[str, Union[type[path], type[str]]],
    expected: int,
) -> None:
    record._desc.name = "test"
    record._field_types = test_input

    hashed_record = hashutil.hash_path_records(mock_target, record)
    assert hashed_record.name == "test"
    assert len(hashed_record.records) == 2
    assert hashed_record.records[0] == record
    assert len(hashed_record.records[1].paths) == expected
    assert len(hashed_record.records[1].digests) == expected


@pytest.mark.parametrize(
    "test_input",
    [
        {},
        {"name": str},
        {"name": str, "test": str},
    ],
)
@patch("flow.record.Record")
def test_hash_path_records_without_paths(record: Record, test_input: dict[str, type[str]]) -> None:
    record._desc.name = "test"
    record._field_types = test_input

    assert hashutil.hash_path_records(Mock(), record) == record


@pytest.mark.parametrize(
    "side_effects,expected",
    [
        ([FileNotFoundError], 0),
        ([IsADirectoryError], 0),
        ([FileNotFoundError, FileNotFoundError], 0),
        ([IsADirectoryError, IsADirectoryError], 0),
        ([FileNotFoundError, IsADirectoryError], 0),
        ([FileNotFoundError, HASHES], 1),
        ([IsADirectoryError, HASHES], 1),
        ([FileNotFoundError, HASHES, IsADirectoryError], 1),
        ([HASHES, FileNotFoundError, HASHES], 2),
        ([HASHES, IsADirectoryError, HASHES], 2),
    ],
)
@patch("flow.record.Record")
def test_hash_path_records_with_exception(
    record: Record,
    mock_target: Mock,
    side_effects: list[Union[type[Exception], tuple[str]]],
    expected: int,
) -> None:
    record._desc.name = "test"
    field_types = {}
    for ii in range(len(side_effects)):
        field_name = f"path_{ii}"
        field_types[field_name] = path
        setattr(record, field_name, "test")
    record._field_types = field_types

    with (
        patch.object(mock_target.fs, "hash", side_effect=side_effects),
        patch.object(mock_target, "resolve", side_effect=resolve_func),
    ):
        hashed_record = hashutil.hash_path_records(mock_target, record)

    if not expected:
        assert hashed_record == record
    else:
        assert len(hashed_record.records[1].paths) == expected
        assert hashed_record.records[1].paths == [resolve_func("test")] * expected
        assert len(hashed_record.records[1].digests) == expected


def test_hash_uri(mock_target: Mock) -> None:
    """Determine hash functions"""
    path = "/test/path"
    with (
        pytest.deprecated_call(),
        patch.object(mock_target, "resolve", side_effect=resolve_func),
    ):
        output = hashutil.hash_uri(mock_target, path)

    assert output[0] == resolve_func(path)
    assert output[1] == HASHES


def test_hash_uri_none() -> None:
    """Determine hash functions"""
    with pytest.deprecated_call(), pytest.raises(FileNotFoundError):
        hashutil.hash_uri(Mock(), None)
