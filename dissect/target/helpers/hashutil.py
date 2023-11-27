from __future__ import annotations

import hashlib
import warnings
from typing import TYPE_CHECKING, BinaryIO, Union

from flow.record import GroupedRecord, Record, RecordDescriptor, fieldtypes

from dissect.target.exceptions import FileNotFoundError, IsADirectoryError

if TYPE_CHECKING:
    from hashlib._hashlib import HASH

    from dissect.target.target import Target

BUFFER_SIZE = 32768

RECORD_NAME = "filesystem/file/digest"
NAME_SUFFIXES = ["_resolved", "_digest"]
RECORD_TYPES = ["path", "digest"]


def _hash(fh: BinaryIO, ctx: Union[HASH, list[HASH]]) -> tuple[str]:
    if not isinstance(ctx, list):
        ctx = [ctx]

    ctx = [c() for c in ctx]
    data = fh.read(BUFFER_SIZE)
    while data:
        [c.update(data) for c in ctx]
        data = fh.read(BUFFER_SIZE)

    return tuple(c.hexdigest() for c in ctx)


def md5(fh: BinaryIO) -> tuple[str]:
    return _hash(fh, hashlib.md5)[0]


def sha1(fh: BinaryIO) -> tuple[str]:
    return _hash(fh, hashlib.sha1)[0]


def sha256(fh: BinaryIO) -> tuple[str]:
    return _hash(fh, hashlib.sha256)[0]


def common(fh: BinaryIO) -> tuple[str]:
    return _hash(fh, [hashlib.md5, hashlib.sha1, hashlib.sha256])


def custom(fh: BinaryIO, algos: list[Union[str, HASH]]) -> tuple[str]:
    if isinstance(algos[0], str):
        ctx = [getattr(hashlib, h) for h in algos]
    else:
        ctx = algos

    return _hash(fh, ctx)


def hash_uri_records(target: Target, record: Record) -> Record:
    """Hash uri paths inside the record."""
    warnings.warn(
        (
            "The hash_uri_records() function is deprecated, and will be removed in dissect.target 3.15. "
            "Use hash_path_records() instead"
        ),
        DeprecationWarning,
    )
    return hash_path_records(target, record)


def hash_path_records(target: Target, record: Record) -> Record:
    """Hash files from path fields inside the record."""
    if target.os == "windows":
        path_type = fieldtypes.windows_path
    else:
        path_type = fieldtypes.posix_path

    hash_records = []

    for field_name, field_type in record._field_types.items():
        if not issubclass(field_type, fieldtypes.path):
            continue

        path = getattr(record, field_name, None)
        if path is None:
            continue

        try:
            resolved_path = target.resolve(str(path))
            path_hash = target.fs.hash(resolved_path)
        except (FileNotFoundError, IsADirectoryError):
            pass
        else:
            resolved_path = path_type(resolved_path)
            record_kwargs = dict()
            record_def = list()

            fields = [resolved_path, path_hash]

            for type, name, field in zip(RECORD_TYPES, NAME_SUFFIXES, fields):
                hashed_field_name = f"{field_name}{name}"
                record_kwargs.update({hashed_field_name: field})
                record_def.append((type, hashed_field_name))

            _record = RecordDescriptor(RECORD_NAME, record_def)

            hash_records.append(_record(**record_kwargs))

    if not hash_records:
        return record

    return GroupedRecord(record._desc.name, [record] + hash_records)


def hash_uri(target: Target, path: str) -> tuple[str, str]:
    """Hash the target path."""
    warnings.warn(
        (
            "The hash_uri() function is deprecated, and will be removed in dissect.target 3.15."
            "Use target.fs.hash() instead"
        ),
        DeprecationWarning,
    )

    if path is None:
        raise FileNotFoundError()

    path = target.resolve(path)
    return (path, target.fs.hash(path))
