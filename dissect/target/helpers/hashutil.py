from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from hashlib._hashlib import HASH

BUFFER_SIZE = 32768


def _hash(fh: BinaryIO, ctx: HASH | list[HASH]) -> tuple[str]:
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


def custom(fh: BinaryIO, algos: list[str | HASH]) -> tuple[str]:
    ctx = [getattr(hashlib, h) for h in algos] if isinstance(algos[0], str) else algos

    return _hash(fh, ctx)
