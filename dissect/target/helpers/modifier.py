import warnings
from functools import partial
from typing import BinaryIO, Callable, Iterator

from flow.record import GroupedRecord, Record, RecordDescriptor, fieldtypes

from dissect.target import Target
from dissect.target.exceptions import FilesystemError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.helpers.hashutil import common
from dissect.target.helpers.utils import StrEnum

RECORD_NAME = "filesystem/file/digest"
NAME_SUFFIXES = ["_resolved", "_digest"]
RECORD_TYPES = ["path", "digest"]


def _resolve_path_types(target: Target, record: Record) -> Iterator[tuple[TargetPath, str]]:
    for field_name, field_type in record._field_types.items():
        if not issubclass(field_type, fieldtypes.path):
            continue

        path = getattr(record, field_name, None)
        if path is None:
            continue

        yield target.resolve(str(path)), field_name


def _create_modified_record(record_name: str, field_name: str, type_info: Iterator[tuple[str, str, str]]):
    record_kwargs = dict()
    record_def = list()
    for type, name, field in type_info:
        hashed_field_name = f"{field_name}{name}"
        record_kwargs.update({hashed_field_name: field})
        record_def.append((type, hashed_field_name))

    _record = RecordDescriptor(record_name, record_def)
    return _record(**record_kwargs)


class Modifier(StrEnum):
    RESOLVE = "resolve"
    HASH = "hash"


def _noop(_target: Target, record: Record):
    return record


MODIFIER_TYPE = Callable[[Target, Record], GroupedRecord]


def get_modifier_function(modifier_type: Modifier) -> MODIFIER_TYPE:
    if func := MODIFIER_MAPPING.get(modifier_type):
        return partial(modify_record, modifier_function=func)

    return _noop


def modify_record(target: Target, record: Record, modifier_function: MODIFIER_TYPE) -> GroupedRecord:
    additional_record = []

    for resolved_path, field_name in _resolve_path_types(target, record):
        try:
            _record = modifier_function(resolved_path, field_name)
        except FilesystemError:
            pass
        else:
            additional_record.append(_record)

    if not additional_record:
        return record

    return GroupedRecord(record._desc.name, [record] + additional_record)


def _resolve_path_records(resolved_path: TargetPath, field_name: str) -> Record:
    """Resolve files from path fields inside the record."""
    type_info = [("path", "_resolved", resolved_path)]
    return _create_modified_record("filesystem/file/resolved", field_name, type_info)


def _hash_path_records(resolved_path: TargetPath, field_name: str) -> Record:
    """Hash files from path fields inside the record."""

    with resolved_path.open() as fh:
        path_hash = common(fh)

    type_info = zip(RECORD_TYPES, NAME_SUFFIXES, [resolved_path, path_hash])

    return _create_modified_record("filesystem/file/digest", field_name, type_info)


MODIFIER_MAPPING = {
    Modifier.RESOLVE: _resolve_path_records,
    Modifier.HASH: _hash_path_records,
}
