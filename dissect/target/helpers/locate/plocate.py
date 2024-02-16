from __future__ import annotations

import platform
import sys
from io import BytesIO
from typing import BinaryIO, Iterable

import zstandard
from dissect.cstruct import cstruct
from dissect.util.stream import RangeStream

# Resource: https://git.sesse.net/?p=plocate @ db.h
plocate_def = """
#define MAGIC 0x00706c6f63617465             /* b'/x00plocate' */

struct header {
    uint32_t version;
    uint32_t hashtable_size;
    uint32_t extra_ht_slots;
    uint32_t num_docids;
    uint64_t hash_table_offset_bytes;
    uint64_t filename_index_offset_bytes;

    /* Version 1 and up only. */
    uint32_t max_version;
    uint32_t zstd_dictionary_length_bytes;
    uint64_t zstd_dictionary_offset_bytes;

    /* Only if max_version >= 2, and only relevant for updatedb. */
    uint64_t directory_data_length_bytes;
    uint64_t directory_data_offset_bytes;
    uint64_t next_zstd_dictionary_length_bytes;
    uint64_t next_zstd_dictionary_offset_bytes;
    uint64_t conf_block_length_bytes;
    uint64_t conf_block_offset_bytes;

    uint8_t check_visibility;
    char padding[7];                         /* padding for alignment */
};

struct file {
    char path[];
};
"""

c_plocate = cstruct()
c_plocate.load(plocate_def)


class PLocateFile:
    """plocate file parser

    The ``plocate.db`` file contains a hashtable and trigrams to enable quick lookups of filenames.

    We've implemented a few methods to gather those for possible future use, but for the PLocatePlugin
    we're only interested in the filepaths stored in the database. Hence we don't use these methods.

    Roughly speaking, the plocate.db file has the following structure:
        - ``header`` (0x70 bytes)
        - zstd compressed ``filename``s (until start of ``filename_index_offset_bytes``),
          possibly including a dictionary
        - hashtables (offset and length in ``header``)
        - directory data (offset and length in ``header``)
        - possible zstd dictionary (offset and length in ``header``)
        - configuration block (offset and length in ``header``)

    No documentation other than the source code is available on the format of this file.

    Resources:
        - https://git.sesse.net/?p=plocate
    """

    HEADER_SIZE = 0x70  # 0x8 bytes magic + 0x68 bytes header
    NUM_OVERFLOW_SLOTS = 16
    TRIGRAM_SIZE_BYTES = 16
    DOCID_SIZE_BYTES = 8

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        magic = int.from_bytes(self.fh.read(8), byteorder="big")
        if magic != c_plocate.MAGIC:
            raise ValueError(f"Invalid plocate file magic. Expected b'/x00plocate', got {magic}")

        self.header = c_plocate.header(self.fh)
        self.dict_data = None

        if self.header.zstd_dictionary_offset_bytes:
            self.dict_data = zstandard.ZstdCompressionDict(self.fh.read(self.header.zstd_dictionary_length_bytes))

        self.compressed_length_bytes = (
            self.header.filename_index_offset_bytes - self.HEADER_SIZE - self.header.zstd_dictionary_length_bytes
        )
        self.ctx = zstandard.ZstdDecompressor(dict_data=self.dict_data)
        self.buf = RangeStream(self.fh, self.fh.tell(), self.compressed_length_bytes)

    def __iter__(self) -> Iterable[PLocateFile]:
        # NOTE: This is a workaround for a pypy3.9 bug
        if platform.python_implementation() == "PyPy" and sys.version_info < (3, 10):
            obj = self.ctx.decompressobj()
            buf = self.buf.read()

            tmp = obj.decompress(buf)
            while unused_data := obj.unused_data:
                obj = self.ctx.decompressobj()
                tmp += obj.decompress(unused_data)

            buf = BytesIO(tmp)

            try:
                while True:
                    file = c_plocate.file(buf)
                    yield file.path.decode(errors="surrogateescape")
            except EOFError:
                return
            return

        with self.ctx.stream_reader(self.buf) as reader:
            try:
                while True:
                    file = c_plocate.file(reader)
                    yield file.path.decode(errors="surrogateescape")
            except EOFError:
                return

    def filename_index(self) -> bytes:
        """Return the filename index of the plocate.db file."""
        self.fh.seek(self.header.filename_index_offset_bytes)
        num_docids = self.header.num_docids
        filename_index_size = num_docids * self.DOCID_SIZE_BYTES
        return self.fh.read(filename_index_size)

    def hashtable(self) -> bytes:
        """Return the hashtable of the plocate.db file."""
        self.fh.seek(self.header.hash_table_offset_bytes)
        hashtable_size = (self.header.hashtable_size + self.NUM_OVERFLOW_SLOTS + 1) * self.TRIGRAM_SIZE_BYTES
        return self.fh.read(hashtable_size)
