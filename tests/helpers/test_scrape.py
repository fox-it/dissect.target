from __future__ import annotations

import io
import os
import random
from typing import TYPE_CHECKING, BinaryIO
from unittest.mock import Mock

import pytest

from dissect.target.helpers import scrape

if TYPE_CHECKING:
    from collections.abc import Iterator

    from pytest_benchmark.fixture import BenchmarkFixture


def test_one_needle() -> None:
    needle = b"ABCD"
    content_size = 50
    chunk_size = len(needle) + content_size
    chunks = [
        b"a" * content_size,
        b"b" * content_size,
        b"c" * content_size,
    ]
    block_size = 70

    noise_block_sizes = [
        int(random.random() * 1000),
        int(random.random() * 1000),
        int(random.random() * 1000),
    ]

    data = (
        os.urandom(noise_block_sizes[0])
        + needle
        + chunks[0]
        + os.urandom(noise_block_sizes[1])
        + needle
        + chunks[1]
        + os.urandom(noise_block_sizes[2])
        + needle
        + chunks[2]
    )

    needle_offsets = [
        noise_block_sizes[0],
        noise_block_sizes[0] + len(needle + chunks[0]) + noise_block_sizes[1],
        noise_block_sizes[0]
        + len(needle + chunks[0])
        + noise_block_sizes[1]
        + len(needle + chunks[1])
        + noise_block_sizes[2],
    ]

    stream = io.BytesIO(data)

    found_needles = list(scrape.find_needles(stream, needles=[needle], block_size=block_size))
    assert found_needles == [
        (needle, needle_offsets[0]),
        (needle, needle_offsets[1]),
        (needle, needle_offsets[2]),
    ]

    stream.seek(0)

    def chunk_reader(fh: BinaryIO, _needle: bytes, offset: int, _chunk_size: int) -> bytes:
        assert needle == _needle
        assert offset in needle_offsets
        assert _chunk_size == chunk_size
        # read chunks _without needle_
        return chunks[needle_offsets.index(offset)]

    found_chunks = list(
        scrape.find_needle_chunks(
            stream,
            needle_chunk_size_map={needle: chunk_size},
            chunk_reader=chunk_reader,
            block_size=block_size,
        )
    )

    assert found_chunks == [
        (needle, needle_offsets[0], chunks[0]),
        (needle, needle_offsets[1], chunks[1]),
        (needle, needle_offsets[2], chunks[2]),
    ]

    stream.seek(0)

    def chunk_parser(_needle: bytes, chunk: bytes) -> Iterator[int]:
        assert _needle == needle
        # check that chunk returned by the default chunk reader is needle + chunk
        assert len(chunk) == chunk_size
        # read first character _after needle_
        yield chunk[len(needle)]

    records = list(
        scrape.scrape_chunks(
            stream,
            needle_chunk_size_map={needle: chunk_size},
            chunk_parser=chunk_parser,
            block_size=block_size,
        )
    )
    assert records == [ord(c) for c in [b"a", b"b", b"c"]]


def test_multiple_needles() -> None:
    needle1 = b"ABCD"
    chunk_size1 = 50

    needle2 = b"EFGHIJ"
    chunk_size2 = 70

    needle3 = b"KLM"
    chunk_size3 = 20

    chunks = [
        needle1 + b"a" * (chunk_size1 - len(needle1)),
        needle2 + b"b" * (chunk_size2 - len(needle2)),
        needle3 + b"c" * (chunk_size3 - len(needle3)),
        needle1 + b"d" * (chunk_size1 - len(needle1)),
        needle2 + b"f" * (chunk_size2 - len(needle2)),
    ]
    block_size = 20

    noise_block_sizes = [
        int(random.random() * 1000),
        int(random.random() * 1000),
        int(random.random() * 1000),
        int(random.random() * 1000),
        int(random.random() * 1000),
    ]

    data = (
        os.urandom(noise_block_sizes[0])
        + chunks[0]
        + os.urandom(noise_block_sizes[1])
        + chunks[1]
        + os.urandom(noise_block_sizes[2])
        + chunks[2]
        + os.urandom(noise_block_sizes[3])
        + chunks[3]
        + os.urandom(noise_block_sizes[4])
        + chunks[4]
    )

    needle_offsets = [
        noise_block_sizes[0],
        noise_block_sizes[0] + len(chunks[0]) + noise_block_sizes[1],
        noise_block_sizes[0] + len(chunks[0]) + noise_block_sizes[1] + len(chunks[1]) + noise_block_sizes[2],
        noise_block_sizes[0]
        + len(chunks[0])
        + noise_block_sizes[1]
        + len(chunks[1])
        + noise_block_sizes[2]
        + len(chunks[2])
        + noise_block_sizes[3],
        noise_block_sizes[0]
        + len(chunks[0])
        + noise_block_sizes[1]
        + len(chunks[1])
        + noise_block_sizes[2]
        + len(chunks[2])
        + noise_block_sizes[3]
        + len(chunks[3])
        + noise_block_sizes[4],
    ]

    stream = io.BytesIO(data)

    found_needles = list(scrape.find_needles(stream, needles=[needle1, needle2, needle3], block_size=block_size))
    assert found_needles == [
        (needle1, needle_offsets[0]),
        (needle2, needle_offsets[1]),
        (needle3, needle_offsets[2]),
        (needle1, needle_offsets[3]),
        (needle2, needle_offsets[4]),
    ]

    stream.seek(0)

    found_chunks = list(
        scrape.find_needle_chunks(
            stream,
            needle_chunk_size_map={
                needle1: chunk_size1,
                needle2: chunk_size2,
                needle3: chunk_size3,
            },
            block_size=block_size,
        )
    )

    assert found_chunks == [
        (needle1, needle_offsets[0], chunks[0]),
        (needle2, needle_offsets[1], chunks[1]),
        (needle3, needle_offsets[2], chunks[2]),
        (needle1, needle_offsets[3], chunks[3]),
        (needle2, needle_offsets[4], chunks[4]),
    ]


def test_multiple_overlapping_needles() -> None:
    needle1 = b"AAA"
    needle2 = b"BBB"
    needle3 = b"BBA"

    # 3 + 5 + 3 + 6 + 3 + 5 = 25
    data = needle1 + b"XXXXX" + needle2 + b"YYYYYY" + needle3 + b"AAZZZ"

    stream = io.BytesIO(data)

    block_size = 10

    # the blocks will be
    # AAAXXXXXBB
    # BYYYYYYBBA
    # AAZZZ

    found_needles = list(scrape.find_needles(stream, needles=[needle1, needle2, needle3], block_size=block_size))
    # 2 full needles + 2 from overlapping 'YYYBBAAAZZZ'
    assert found_needles == [
        (needle1, 0),
        (needle2, 8),
        (needle3, 17),
        (needle1, 19),
    ]


def test_find_needle() -> None:
    buf = b"A" * 100 + b"needle" + b"B" * 100

    assert list(scrape.find_needles(io.BytesIO(buf), [b"needle"])) == [(b"needle", 100)]
    assert list(scrape.find_needles(io.BytesIO(buf), b"needle")) == [(b"needle", 100)]

    with pytest.raises(ValueError, match="At least one needle value must be provided"):
        list(scrape.find_needles(io.BytesIO(buf), []))

    with pytest.raises(ValueError, match="Start offset must be less than end offset"):
        list(scrape.find_needles(io.BytesIO(buf), [b"needle"], start=100, end=100))

    mock_progress = Mock()
    list(scrape.find_needles(io.BytesIO(buf), [b"needle"], progress=mock_progress))
    mock_progress.assert_called_once_with(0)

    buf = io.BytesIO(b"A" * 100 + b"needle" + b"B" * 100 + b"needle" + b"C" * 100 + b"needle" + b"D" * 100)
    for i, (_, offset) in enumerate(scrape.find_needles(buf, [b"needle"], lock_seek=False, block_size=100)):
        if i == 0:
            assert offset == 100
            buf.seek(300)

        if i == 1:
            assert offset == 312

    assert i == 1


@pytest.mark.parametrize(
    ("buf", "encoding", "reverse", "ascii", "expected"),
    [
        (b"foo\xaa\xaa", "utf-8", False, True, "foo"),
        (b"\xaa\xaafoo", "utf-8", True, True, "foo"),
        (b"foo\x00bar", "utf-8", False, True, "foo"),
        (b"foo\x00bar", "utf-8", True, True, "bar"),
        (b"f\x00o\x00o\x00\xee\xee", "utf-16-le", False, True, "foo"),
        (b"f\x00o\x00o\x00\xee\xee", "utf-16-le", False, False, "foo\ueeee"),
        (b"\xee\xee\x00f\x00o\x00o\x00", "utf-16-le", True, True, "foo"),
    ],
)
def test_recover_string(buf: bytes, encoding: str, reverse: bool, ascii: bool, expected: str) -> None:
    assert scrape.recover_string(buf, encoding, reverse=reverse, ascii=ascii) == expected


@pytest.mark.benchmark
def test_benchmark_find_needles(benchmark: BenchmarkFixture) -> None:
    buf = b"A" * 100 + b"needle" + b"B" * 100
    needles = [b"needle"]
    benchmark(lambda: list(scrape.find_needles(io.BytesIO(buf), needles)))
