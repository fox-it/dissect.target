from __future__ import annotations

import io
import re
import string
from typing import TYPE_CHECKING, BinaryIO, Callable, Union

if TYPE_CHECKING:
    import logging
    from collections.abc import Iterator

    from dissect.target.helpers.record import TargetRecordDescriptor


Needle = Union[bytes, re.Pattern]


def find_needles(
    fh: BinaryIO,
    needles: Needle | list[Needle],
    *,
    start: int | None = None,
    end: int | None = None,
    lock_seek: bool = True,
    block_size: int = io.DEFAULT_BUFFER_SIZE,
    progress: Callable[[int], None] | None = None,
) -> Iterator[tuple[bytes, int]]:
    """Yields needles and their offsets found in provided byte stream.

    Args:
        fh: The byte stream to search for needles.
        needles: The list of bytes needles to search for.
        start: The offset to start searching from.
        end: The offset to stop searching at.
        lock_seek: Whether the file position is maintained by the scraper or the consumer.
                   Setting this to ``False`` will allow the consumer to seek the file pointer, i.e. to skip forward.
        block_size: The block size to use for reading from the byte stream.
        progress: A function to call with the current offset.
    """

    if not isinstance(needles, list):
        needles = [needles]

    if not needles:
        raise ValueError("At least one needle value must be provided")

    if start is not None and end is not None and start >= end:
        raise ValueError("Start offset must be less than end offset")

    max_needle_len = max(len(n.pattern if isinstance(n, re.Pattern) else n) for n in needles)
    overlap_len = max_needle_len

    offset = fh.tell() if start is None else start
    current_block = b""

    while offset < end if end is not None else True:
        if lock_seek:
            fh.seek(offset)
        else:
            offset = fh.tell()

        read_size = min(block_size, end - offset) if end is not None else block_size
        if not (next_block := fh.read(read_size)):
            break

        if progress:
            progress(offset)

        overlap = current_block[-overlap_len:] if overlap_len > 0 else b""
        current_block = overlap + next_block
        current_block_offset = offset - len(overlap)

        # Look for a needle in a current block
        last_needle_pos = -1
        last_needle_end = 0
        while True:
            needle_positions = [
                (pos, needle)
                for needle in needles
                if (
                    pos := (match.start(0) if (match := needle.search(current_block, last_needle_pos + 1)) else -1)
                    if isinstance(needle, re.Pattern)
                    else current_block.find(needle, last_needle_pos + 1)
                )
                > -1
            ]

            if not needle_positions:
                break

            closest_needle_pos, closest_needle = min(needle_positions)
            yield closest_needle, current_block_offset + closest_needle_pos

            last_needle_pos = closest_needle_pos
            last_needle_end = last_needle_pos + 1

        # The size of the data from the current block that will be prepended to the next block
        overlap_len = min(len(current_block) - last_needle_end, max_needle_len)

        offset += block_size


def _read_plain_chunk(fh: BinaryIO, needle: Needle, offset: int, chunk_size: int) -> bytes:
    """Read chunk from a byte stream for provided needle, offset and chunk size."""
    fh.seek(offset)
    return fh.read(chunk_size)


def find_needle_chunks(
    fh: BinaryIO,
    needle_chunk_size_map: dict[Needle, int],
    chunk_reader: Callable[[BinaryIO, Needle, int, int], bytes] | None = None,
    lock_seek: bool = True,
    block_size: int = io.DEFAULT_BUFFER_SIZE,
) -> Iterator[tuple[bytes, int, bytes]]:
    """Yields tuples with an offset, a needle and a byte chunk found in provided byte stream.

    Args:
        fh: The byte stream to search for needles.
        needle_chunk_size_map: A dictionary with needle bytes as keys and chunk sizes as values.
        chunk_reader: A function to read a chunk from a byte stream for provided needle, offset and chunk size.
        lock_seek: Whether the file position is maintained by the scraper or the consumer.
                   Setting this to ``False`` wil allow the consumer to seek the file pointer, i.e. to skip forward.
        block_size: The block size to use for reading from the byte stream.
    """
    chunk_reader = chunk_reader or _read_plain_chunk

    needles = list(needle_chunk_size_map.keys())
    for needle, offset in find_needles(fh, needles, lock_seek=lock_seek, block_size=block_size):
        yield (needle, offset, chunk_reader(fh, needle, offset, needle_chunk_size_map[needle]))


def scrape_chunks(
    fh: BinaryIO,
    needle_chunk_size_map: dict[Needle, int],
    chunk_parser: Callable[[Needle, bytes], Iterator[TargetRecordDescriptor]],
    chunk_reader: Callable[[BinaryIO, Needle, int, int], bytes] | None = None,
    block_size: int = io.DEFAULT_BUFFER_SIZE,
    log: logging.Logger | None = None,
) -> Iterator[TargetRecordDescriptor]:
    """Yields records scraped from chunks found in a provided byte stream.

    Args:
        fh: The byte stream to search for needles.
        needle_chunk_size_map: A dictionary with needle bytes as keys and chunk sizes as values.
        chunk_parser: A function to parse a chunk and yield records.
        chunk_reader: A function to read a chunk from a byte stream for provided needle, offset and chunk size.
        block_size: The block size to use for reading from the byte stream.
        log: A logger to use for logging.
    """

    chunk_count = 0
    record_count = 0

    chunk_stream = find_needle_chunks(
        fh,
        needle_chunk_size_map,
        block_size=block_size,
        chunk_reader=chunk_reader or _read_plain_chunk,
    )

    for needle, _, chunk in chunk_stream:
        try:
            for record in chunk_parser(needle, chunk):
                yield record
                record_count += 1
            chunk_count += 1
        except Exception as e:  # noqa: PERF203
            if log:
                log.warning("Chunk parsing failed with %r", e)

    if log:
        log.debug("Scraped %d chunks with %d records", chunk_count, record_count)


def recover_string(buf: bytes, encoding: str, *, reverse: bool = False, ascii: bool = True) -> str:
    """Recover the longest possible string from a byte buffer, forward or reverse.

    Args:
        buf: The byte buffer to recover a string from.
        encoding: The encoding to use for decoding the buffer.
        reverse: Whether to recover the string from the end of the buffer.
        ascii: Whether to recover only ASCII characters.
    """
    if reverse:
        decoded = ""
        error_count = 0
        max_error_count = 8  # Arbitrary limit

        for i in range(1, len(buf) + 1):
            try:
                decoded = buf[-i:].decode(encoding)
                error_count = 0
            except UnicodeDecodeError:  # noqa: PERF203
                error_count += 1

                if error_count > max_error_count:
                    break

        decoded = decoded.split("\x00")[-1]

        if ascii:
            for i in range(1, len(decoded) + 1):
                if decoded[-i] not in string.printable:
                    decoded = decoded[-i + 1 :]
                    break
    else:
        try:
            decoded = buf.decode(encoding)
        except UnicodeDecodeError as e:
            decoded = buf[: e.start].decode(encoding)

        decoded = decoded.split("\x00")[0]

        if ascii:
            for i in range(len(decoded)):
                if decoded[i] not in string.printable:
                    decoded = decoded[:i]
                    break

    return decoded
