"""Scan a binary for (raw_key, encrypted-RSA-blob) candidates by structural regex.

Handles both field orders (<key>-<pad>-<blob> and <blob>-<pad>-<key>), any gap length
(0 = adjacent, or zero-padding between the fields), inner-edge NULLs, and up to
MAX_RECLAIM NULL bytes bleeding into the outer padding at each field's outer edge.
"""

from __future__ import annotations

import functools
import re
from typing import TYPE_CHECKING

from .models import RawKeyCandidate

if TYPE_CHECKING:
    from collections.abc import Iterator


KEY_LEN = 32
IV_LEN = 16
BLOB_LEN = 270

MAX_RECLAIM = 2  # NULLs reclaimed off each OUTER edge
MAX_GAP = 18  # inter-field zero-padding: 0 (adjacent) .. this many bytes
MAX_BLOB_NULLS = 40  # a real encrypted blob is dense
MAX_KEY_NULLS = 8  # a real 32-byte key averages <1 null; reject header/marker junk

INNER_ZERO_RUN = 5  # a real dense blob has no zero-run this long (rejects DigestInfo-style false blobs)
ZERO_RUN = b"\x00" * INNER_ZERO_RUN


# Pattern generators
def _kpb(a: int, b: int, key_len: int) -> re.Pattern:
    """Generate a regex pattern for <key><pad><blob> structure with given parameters."""
    pattern = rb"""
        (?<=\x00)                     # preceded by outer NUL padding
        (?=                           # zero-width lookahead -> overlapping matches
            (?P<key>
                \x00{%d}              # a: reclaimed leading NUL bytes (outer edge)
                [^\x00]               # first real key byte
                .{%d}                 # rest of the key
            )
            \x00{0,%d}                # inter-field zero padding (gap)
            (?P<blob>
                .{%d}                 # dense blob body
                [^\x00]               # last real blob byte (outer edge)
                \x00{%d}              # b: reclaimed trailing NUL bytes
            )
            \x00                      # trailing outer NUL padding
        )
    """ % (a, key_len - 1 - a, MAX_GAP, BLOB_LEN - 1 - b, b)
    return re.compile(pattern, re.DOTALL | re.VERBOSE)


def _bpk(a: int, b: int, key_len: int) -> re.Pattern:
    """Generate a regex pattern for <blob><pad><key> structure with given parameters."""
    pattern = rb"""
        (?<=\x00)
        (?=
            (?P<blob>
                \x00{%d}              # a: reclaimed leading NUL bytes (outer edge)
                [^\x00]               # first real blob byte
                .{%d}                 # rest of the blob
            )
            \x00{0,%d}                # inter-field zero padding (gap)
            (?P<key>
                .{%d}                 # key body
                [^\x00]               # last real key byte (outer edge)
                \x00{%d}              # b: reclaimed trailing NUL bytes
            )
            \x00                      # trailing outer NUL padding
        )
    """ % (a, BLOB_LEN - 1 - a, MAX_GAP, key_len - 1 - b, b)
    return re.compile(pattern, re.DOTALL | re.VERBOSE)


@functools.cache
def _build_patterns(key_len: int = 32, max_reclaim: int = 1) -> tuple:
    return tuple(
        gen(a, b, key_len) for a in range(max_reclaim + 1) for b in range(max_reclaim + 1) for gen in (_kpb, _bpk)
    )


# Raw key+blob finder
def iter_raw_key_candidates(raw: bytes, max_reclaim: int = MAX_RECLAIM) -> Iterator[RawKeyCandidate]:
    """Yield RawKeyCandidate instances found in the raw bytes."""
    seen: set[tuple[bytes, bytes]] = set()

    for key_len in (KEY_LEN, KEY_LEN + IV_LEN):  # check for 32-byte keys and 48-byte keys (32 + 16)
        for rx in _build_patterns(key_len=key_len, max_reclaim=max_reclaim):
            for m in rx.finditer(raw):
                key, blob = m.group("key"), m.group("blob")
                if len(key) != KEY_LEN or len(blob) != BLOB_LEN:
                    continue
                if blob.count(0) > MAX_BLOB_NULLS:
                    continue
                if key.count(0) > MAX_KEY_NULLS:
                    continue
                if ZERO_RUN in blob:
                    continue
                pair = (key, blob)
                if pair in seen:
                    continue
                seen.add(pair)
                yield RawKeyCandidate(key, blob, m.start("key"), m.start("blob"))
