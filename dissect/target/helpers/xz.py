import io
from binascii import crc32
from typing import BinaryIO

from dissect.util.stream import OverlayStream


def repair_lzma_stream(fh: BinaryIO) -> BinaryIO:
    """Repair CRC32 checksums for all headers in an XZ stream.

    FortiOS XZ files have (on purpose) corrupt streams which they read using a modified ``xz`` binary.
    The only thing changed are the CRC32 checksums, so partially parse the XZ file and fix all of them.

    References:
        - https://tukaani.org/xz/xz-file-format-1.1.0.txt
        - https://github.com/Rogdham/python-xz

    Args:
        fh: A file-like object of an LZMA stream to repair.
    """
    size = fh.seek(0, io.SEEK_END)
    repaired = OverlayStream(fh, size)
    fh.seek(0)

    header = fh.read(12)
    # Check header magic
    if header[:6] != b"\xfd7zXZ\x00":
        raise ValueError("Not an XZ file")

    # Add correct header CRC32
    repaired.add(8, _crc32(header[6:8]))

    fh.seek(-12, io.SEEK_END)
    footer = fh.read(12)

    # Check footer magic
    if footer[10:12] != b"YZ":
        raise ValueError("Not an XZ file")

    # Add correct footer CRC32
    repaired.add(fh.tell() - 12, _crc32(footer[4:10]))

    backward_size = (int.from_bytes(footer[4:8], "little") + 1) * 4
    fh.seek(-12 - backward_size, io.SEEK_END)
    index = fh.read(backward_size)

    # Add correct index CRC32
    repaired.add(fh.tell() - 4, _crc32(index[:-4]))

    # Parse the index
    isize, nb_records = _mbi(index[1:])
    index = index[1 + isize : -4]
    records = []
    for _ in range(nb_records):
        if not index:
            raise ValueError("index size")

        isize, unpadded_size = _mbi(index)
        if not unpadded_size:
            raise ValueError("index record unpadded size")

        index = index[isize:]
        if not index:
            raise ValueError("index size")

        isize, uncompressed_size = _mbi(index)
        if not uncompressed_size:
            raise ValueError("index record uncompressed size")

        index = index[isize:]
        records.append((unpadded_size, uncompressed_size))

    block_start = size - 12 - backward_size
    blocks_len = sum((unpadded_size + 3) & ~3 for unpadded_size, _ in records)
    block_start -= blocks_len

    # Iterate over all blocks and add the correct block header CRC32
    for unpadded_size, _ in records:
        fh.seek(block_start)

        block_header = fh.read(1)
        block_header_size = (block_header[0] + 1) * 4
        block_header += fh.read(block_header_size - 1)
        repaired.add(fh.tell() - 4, _crc32(block_header[:-4]))

        block_start += (unpadded_size + 3) & ~3

    return repaired


def _mbi(data: bytes) -> tuple[int, int]:
    value = 0
    for size, byte in enumerate(data):
        value |= (byte & 0x7F) << (size * 7)
        if not byte & 0x80:
            return size + 1, value
    raise ValueError("Invalid mbi")


def _crc32(data: bytes) -> bytes:
    return int.to_bytes(crc32(data), 4, "little")
