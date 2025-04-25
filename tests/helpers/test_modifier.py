from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import Mock, mock_open, patch

import pytest
from flow.record.fieldtypes import command, digest, path

from dissect.target.exceptions import FileNotFoundError, IsADirectoryError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.record_modifier import (
    Modifier,
    ModifierFunc,
    get_modifier_function,
)
from tests.helpers.test_hashutil import HASHES

if TYPE_CHECKING:
    from flow.record import Record

    from dissect.target.target import Target


@pytest.fixture
def hash_function() -> ModifierFunc:
    return get_modifier_function(Modifier.HASH)


@pytest.fixture
def resolve_function() -> ModifierFunc:
    return get_modifier_function(Modifier.RESOLVE)


@pytest.mark.parametrize(
    ("test_input", "expected_records"),
    [
        ({"name": path}, 2),
        ({"name": path, "test": path}, 3),
        ({"name": path, "test": str}, 2),
        ({"name": command}, 2),
    ],
)
@patch("flow.record.Record")
def test_hash_path_records_with_paths(
    record: Record,
    hash_function: ModifierFunc,
    target_win: Mock,
    test_input: dict[str, type[path | str]],
    expected_records: int,
) -> None:
    record._desc.name = "test"
    record._field_types = test_input

    path_field_names = [key for key, value in test_input.items() if value is path]

    with (
        patch.object(TargetPath, "open", mock_open(read_data=b"")),
        patch("dissect.target.helpers.fsutil.TargetPath.exists", return_value=True),
        patch("dissect.target.helpers.fsutil.TargetPath.is_file", return_value=True),
        patch("dissect.target.helpers.record_modifier.common", return_value=HASHES),
    ):
        hashed_record = hash_function(target_win, record)

    assert hashed_record.name == "test"
    assert len(hashed_record.records) == expected_records
    assert hashed_record.records[0] == record

    for name, _record in zip(path_field_names, hashed_record.records[1:]):
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
    hash_function: ModifierFunc,
    test_input: dict[str, type[str]],
) -> None:
    record._desc.name = "test"
    record._field_types = test_input

    assert hash_function(Mock(), record) == record


@pytest.mark.parametrize(
    ("side_effects", "expected"),
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
    hash_function: ModifierFunc,
    target_win: Target,
    side_effects: list[type[Exception] | tuple[str]],
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

    mocked_open = mock_open()
    mocked_open.configure_mock(**{"return_value.__enter__.side_effect": side_effects})

    with (
        patch.object(TargetPath, "open", mocked_open),
        patch("dissect.target.helpers.record_modifier.common", return_value=HASHES),
    ):
        hashed_record = hash_function(target_win, record)

    if not expected:
        assert hashed_record == record
    else:
        for _record, key in zip(hashed_record.records[1:], found_type_names):
            assert getattr(_record, f"{key}_resolved") == "test"
            assert getattr(_record, f"{key}_digest").__dict__ == digest(HASHES).__dict__


@patch("flow.record.Record")
def test_resolved_modifier(record: Record, target_win: Target, resolve_function: ModifierFunc) -> None:
    record._desc.name = "test"
    record._field_types = {"name": path}

    resolved_record = resolve_function(target_win, record)

    for _record in resolved_record.records[1:]:
        assert _record.name_resolved is not None
        assert not hasattr(_record, "name_digest")
