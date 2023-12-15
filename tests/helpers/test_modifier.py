from typing import Callable, Union
from unittest.mock import Mock, patch

import pytest
from flow.record import Record
from flow.record.fieldtypes import path

from dissect.target import Target
from dissect.target.helpers.modifier import (
    MODIFIER_TYPE,
    Modifier,
    get_modifier_function,
)
from tests.helpers.test_hashutil import HASHES, mock_target, resolve_func


@pytest.fixture
def hash_function() -> MODIFIER_TYPE:
    return get_modifier_function(Modifier.HASH)


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
    hash_function: MODIFIER_TYPE,
    mock_target: Mock,
    test_input: dict[str, Union[type[path], type[str]]],
    expected_records: int,
) -> None:
    record._desc.name = "test"
    record._field_types = test_input

    record_names = [key for key, value in test_input.items() if value is path]

    hashed_record = hash_function(mock_target, record)
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
def test_hash_path_records_without_paths(
    record: Record,
    hash_function: MODIFIER_TYPE,
    test_input: dict[str, type[str]],
) -> None:
    record._desc.name = "test"
    record._field_types = test_input

    assert hash_function(Mock(), record) == record


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
    hash_function: MODIFIER_TYPE,
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
        hashed_record = hash_function(mock_target, record)

    if not expected:
        assert hashed_record == record
    else:
        for _record, key in zip(hashed_record.records[1:], found_type_names):
            assert getattr(_record, f"{key}_resolved") == resolve_func("test")
            assert getattr(_record, f"{key}_digest").__dict__ == digest(HASHES).__dict__
