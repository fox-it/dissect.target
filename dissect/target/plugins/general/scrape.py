import io

from typing import Generator, List, Tuple, Dict, Callable, BinaryIO

from dissect.target import plugin
from dissect.target.helpers.record import TargetRecordDescriptor


class ScrapePlugin(plugin.Plugin):

    __namespace__ = "scrape"

    def check_compatible(self):
        return True

    @plugin.internal
    def find_needles(
        self,
        fh: BinaryIO,
        needles: List[bytes],
        block_size: int = io.DEFAULT_BUFFER_SIZE,
    ) -> Generator[Tuple[bytes, int], None, None]:
        """Yields needles and their offsets found in provided byte stream"""

        if not needles:
            raise ValueError("At least one needle value must be provided")

        max_needle_len = max([len(n) for n in needles])
        overlap_len = max_needle_len
        current_block = b""

        while True:
            next_block_offset = fh.tell()
            next_block = fh.read(block_size)

            if not next_block:
                break

            overlap = current_block[-overlap_len:] if overlap_len > 0 else b""
            current_block = overlap + next_block

            current_block_offset = next_block_offset - len(overlap)

            # Look for a needle in a current block
            last_needle_pos = -1
            last_needle_end = 0
            while True:
                needle_positions = [
                    (pos, needle)
                    for pos, needle in [(current_block.find(needle, last_needle_pos + 1), needle) for needle in needles]
                    if pos > -1
                ]

                if not needle_positions:
                    break

                closest_needle_pos, closest_needle = min(needle_positions)

                # just in case `fh` is changed outside the function
                saved_offset = fh.tell()
                try:
                    yield closest_needle, current_block_offset + closest_needle_pos
                finally:
                    fh.seek(saved_offset)

                last_needle_pos = closest_needle_pos
                last_needle_end = last_needle_pos + 1

            # the size of the data from the current block that will be prepended to the next block
            overlap_len = min(len(current_block) - last_needle_end, max_needle_len)

    @plugin.internal
    def find_needle_chunks(
        self,
        fh: BinaryIO,
        needle_chunk_size_map: Dict[bytes, int],
        block_size: int = io.DEFAULT_BUFFER_SIZE,
        chunk_reader: Callable[[BinaryIO, bytes, int, int], bytes] = None,
    ) -> Generator[Tuple[bytes, int, bytes], None, None]:
        """Yields tuples with an offset, a needle and a byte chunk found in provided byte stream."""

        chunk_reader = chunk_reader or read_plain_chunk

        needles = list(needle_chunk_size_map.keys())
        for needle, offset in self.find_needles(fh, needles=needles, block_size=block_size):
            saved_offset = fh.tell()
            chunk_size = needle_chunk_size_map[needle]
            try:
                yield (needle, offset, chunk_reader(fh, needle, offset, chunk_size))
            finally:
                fh.seek(saved_offset)

    @plugin.internal
    def scrape_chunks(
        self,
        fh: BinaryIO,
        needle_chunk_size_map: Dict[bytes, int],
        chunk_parser: Callable[[bytes, bytes], Generator],
        chunk_reader: Callable[[BinaryIO, bytes, int, int], bytes] = None,
        block_size: int = io.DEFAULT_BUFFER_SIZE,
    ) -> Generator[TargetRecordDescriptor, None, None]:
        """Yields records scraped from chunks found in a provided byte stream"""

        chunk_count = 0
        record_count = 0

        chunk_stream = self.find_needle_chunks(
            fh,
            needle_chunk_size_map,
            block_size=block_size,
            chunk_reader=chunk_reader,
        )

        for needle, _, chunk in chunk_stream:
            try:
                for record in chunk_parser(needle, chunk):
                    yield record
                    record_count += 1
                chunk_count += 1
            except Exception as e:
                self.target.log.warn(f"Chunk parsing failed with {e!r}")

        self.target.log.info(f"Scraped {chunk_count} chunks with {record_count} records")

    @plugin.internal
    def scrape_chunks_from_disks(
        self,
        chunk_parser: Callable[[bytes, bytes], Generator],
        needle_chunk_size_map: Dict[bytes, int] = None,
        needle: bytes = None,
        chunk_size: int = None,
        chunk_reader: Callable[[BinaryIO, bytes, int, int], bytes] = None,
        block_size: int = io.DEFAULT_BUFFER_SIZE,
    ) -> Generator[TargetRecordDescriptor, None, None]:
        """Yields records scraped from chunks found in target.disks"""

        if needle_chunk_size_map and (needle or chunk_size):
            raise ValueError("Either `needle_chunk_size_map` or both `needle` and `chunk_size` must be provided")

        if (needle and not chunk_size) or (not needle and chunk_size):
            raise ValueError("Both `needle` and `chunk_size` must be provided")
        else:
            needle_chunk_size_map = {needle: chunk_size}

        for disk in self.target.disks:
            # reset pointer to the start of a disk
            disk.seek(0)
            yield from self.scrape_chunks(
                disk,
                needle_chunk_size_map=needle_chunk_size_map,
                chunk_parser=chunk_parser,
                chunk_reader=chunk_reader,
                block_size=block_size,
            )

    @plugin.internal
    def scrape_needles_from_disks(
        self,
        needles: List[bytes] = None,
        needle: bytes = None,
        block_size: int = io.DEFAULT_BUFFER_SIZE,
    ) -> Generator[Tuple[BinaryIO, bytes, int], None, None]:
        """Yields bytestream / needle / offset tuples, scraped from target.disks"""

        if needles and needle:
            raise ValueError("Either `needles` values or a signle `needle` value must be provided")
        elif not needles and not needle:
            raise ValueError("At least one needle value must be provided")

        if needle:
            needles = [needle]

        for disk in self.target.disks:
            # reset pointer to the start of a disk
            disk.seek(0)
            for needle, offset in self.find_needles(disk, needles=needles, block_size=block_size):
                yield disk, needle, offset


def read_plain_chunk(fh: BinaryIO, needle: bytes, offset: int, chunk_size: int) -> bytes:
    """Read chunk from a byte stream for provided needle, offset and chunk size"""
    fh.seek(offset)
    return fh.read(chunk_size)
