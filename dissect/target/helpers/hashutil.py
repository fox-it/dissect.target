from __future__ import annotations

import hashlib
import warnings
from typing import TYPE_CHECKING, BinaryIO, Union

from flow.record import Record

from dissect.target.exceptions import FileNotFoundError

if TYPE_CHECKING:
    from hashlib._hashlib import HASH

    from dissect.target.target import Target

BUFFER_SIZE = 32768


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


def hash_uri(target: Target, path: str) -> tuple[str, str]:
    """Hash the target path."""
    warnings.warn(
        (
            "The hash_uri() function is deprecated, and will be removed in dissect.target 3.15. "
            "Use target.fs.hash() instead"
        ),
        DeprecationWarning,
    )

    if path is None:
        raise FileNotFoundError()

    path = str(target.resolve(path))
    return (path, target.fs.hash(path))


def hash_uri_records(target: Target, record: Record) -> Record:
    """Hash uri paths inside the record."""

    from dissect.target.helpers.record_modifier import Modifier, get_modifier_function

    warnings.warn(
        (
            "The hash_uri_records() function is deprecated, and will be removed in dissect.target 3.15. "
            "Use hash_path_records() instead"
        ),
        DeprecationWarning,
    )
    func = get_modifier_function(Modifier.HASH)
    return func(target, record)
