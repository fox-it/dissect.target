from typing import Union
from unittest.mock import Mock, patch

import pytest
from flow.record import Record
from flow.record.fieldtypes import digest, path

import dissect.target.helpers.hashutil as hashutil
from dissect.target.exceptions import FileNotFoundError, IsADirectoryError

HASHES = ("CAFEF00D" * 4, "F4CEF001" * 5, "DEADBEEF" * 8)


@pytest.fixture
def mock_target(target_win) -> Mock:
    target_win.fs.hash = lambda path: HASHES
    target_win.resolve = lambda path: path
    return target_win


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
    "test_input, expected_records",
    [
        ({"name": path}, 2),
        ({"name": path, "test": path}, 3),
        ({"name": path, "test": str}, 2),
    ],
)
@patch("flow.record.Record")
def test_hash_path_records_with_paths(
    record: Record,
    mock_target: Mock,
    test_input: dict[str, Union[type[path], type[str]]],
    expected_records: int,
) -> None:
    record._desc.name = "test"
    record._field_types = test_input

    record_names = [key for key, value in test_input.items() if value is path]

    hashed_record = hashutil.hash_path_records(mock_target, record)
    assert hashed_record.name == "test"
    assert len(hashed_record.records) == expected_records
    assert hashed_record.records[0] == record

    _record = hashed_record.records[1]

    for name, _record in zip(record_names, hashed_record.records[1:]):
        assert getattr(_record, f"{name}_resolved") is not None
        assert getattr(_record, f"{name}_digest").__dict__ == digest(HASHES).__dict__


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
    found_type_names = []
    for idx, data in enumerate(side_effects):
        field_name = f"path_{idx}"
        field_types[field_name] = path
        setattr(record, field_name, "test")
        if data is HASHES:
            found_type_names.append(field_name)

    record._field_types = field_types

    with (
        patch.object(mock_target.fs, "hash", side_effect=side_effects),
        patch.object(mock_target, "resolve", side_effect=resolve_func),
    ):
        hashed_record = hashutil.hash_path_records(mock_target, record)

    if not expected:
        assert hashed_record == record
    else:
        for _record, key in zip(hashed_record.records[1:], found_type_names):
            assert getattr(_record, f"{key}_resolved") == resolve_func("test")
            assert getattr(_record, f"{key}_digest").__dict__ == digest(HASHES).__dict__


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
