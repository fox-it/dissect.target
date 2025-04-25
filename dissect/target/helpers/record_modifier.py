from __future__ import annotations

import logging
from functools import partial
from typing import TYPE_CHECKING, Callable

from flow.record import GroupedRecord, Record, RecordDescriptor, fieldtypes

from dissect.target.exceptions import FileNotFoundError, FilesystemError
from dissect.target.helpers.hashutil import common
from dissect.target.helpers.utils import StrEnum
from dissect.target.target import Target

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.target.helpers.fsutil import TargetPath

__all__ = ("Modifier", "ModifierFunc", "get_modifier_function")

RECORD_NAME = "filesystem/file/digest"
NAME_SUFFIXES = ["_resolved", "_digest"]
RECORD_TYPES = ["path", "digest"]

ModifierFunc = Callable[[Target, Record], GroupedRecord]


class Modifier(StrEnum):
    RESOLVE = "resolve"
    HASH = "hash"


def _create_modified_record(
    record_name: str, field_name: str, field_info: Iterable[tuple[str, str, TargetPath]]
) -> Record:
    record_kwargs = {}
    record_def = []
    for type, name_suffix, data in field_info:
        extended_field_name = f"{field_name}{name_suffix}"
        record_kwargs.update({extended_field_name: data})
        record_def.append((type, extended_field_name))

    _record = RecordDescriptor(record_name, record_def)
    return _record(**record_kwargs)


def _resolve_path_records(field_name: str, resolved_path: TargetPath) -> Record:
    """Resolve files from path fields inside the record."""
    type_info = [("path", "_resolved", resolved_path)]
    return _create_modified_record("filesystem/file/resolved", field_name, type_info)


def _hash_path_records(field_name: str, resolved_path: TargetPath) -> Record:
    """Hash files from path fields inside the record.

    Args:
        field_name: Name of the field.
        resolved_path: Path to the file we should hash.

    Raises:
        FileNotFoundError: Raised if the provided ``resolved_path`` does not exist or is not a file on the target.

    Returns:
        Modified record with digests of path field types.
    """

    if not resolved_path.exists() or not resolved_path.is_file():
        raise FileNotFoundError(f"Path not found or is not a file: '{resolved_path}'")

    with resolved_path.open() as fh:
        path_hash = common(fh)

    type_info = zip(RECORD_TYPES, NAME_SUFFIXES, [resolved_path, path_hash])

    return _create_modified_record("filesystem/file/digest", field_name, type_info)


MODIFIER_MAPPING = {
    Modifier.RESOLVE: _resolve_path_records,
    Modifier.HASH: _hash_path_records,
}


def _resolve_path_types(target: Target, record: Record) -> Iterator[tuple[str, TargetPath]]:
    for field_name, field_type in record._field_types.items():
        if not issubclass(field_type, (fieldtypes.path, fieldtypes.command)):
            continue

        path = getattr(record, field_name, None)
        if path is None:
            continue

        if isinstance(path, fieldtypes.command):
            path = path.executable

        yield field_name, target.resolve(str(path))


def modify_record(target: Target, record: Record, modifier_function: ModifierFunc) -> GroupedRecord:
    additional_records = []

    for field_name, resolved_path in _resolve_path_types(target, record):
        try:
            _record = modifier_function(field_name, resolved_path)
        except FilesystemError as e:  # noqa: PERF203
            level = logging.INFO if isinstance(e, FileNotFoundError) else logging.WARNING
            target.log.log(
                level,
                "Unable to modify record '%s' with function '%s': %s",
                record._desc.name,
                modifier_function.__name__,
                e,
            )
            target.log.debug("", exc_info=e)

        else:
            additional_records.append(_record)

    if not additional_records:
        return record

    return GroupedRecord(record._desc.name, [record, *additional_records])


def _noop(_target: Target, record: Record) -> Record:
    return record


def get_modifier_function(modifier_type: Modifier) -> ModifierFunc:
    if func := MODIFIER_MAPPING.get(modifier_type):
        return partial(modify_record, modifier_function=func)

    return _noop
