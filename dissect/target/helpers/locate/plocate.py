from typing import IO, Iterator

import zstandard
from dissect.cstruct import cstruct

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
}
"""

c_plocate = cstruct()
c_plocate.load(plocate_def)


class PLocateFileParser:
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

    def __init__(self, file_handler: IO):
        self.fh = file_handler

        magic = int.from_bytes(self.fh.read(8), byteorder="big")
        if magic != c_plocate.MAGIC:
            raise ValueError("is not a valid plocate file")

        self.header = c_plocate.header(self.fh)

    def paths(self) -> Iterator[str]:
        """
        A zstd compressed blob with null byte separated paths is located after the file header.
        The compression was done either with or without a dictionary. This is specified by the
        zstd_dictionary_length_bytes / zstd_dictionary_offset_bytes values in the header. If there is no dictionary,
        they are both 0.
        """
        self.fh.seek(self.HEADER_SIZE)
        if self.header.zstd_dictionary_offset_bytes == 0:
            dict_data = None
        else:
            dict_data = zstandard.ZstdCompressionDict(self.fh.read(self.header.zstd_dictionary_length_bytes))

        compressed_length_bytes = (
            self.header.filename_index_offset_bytes - self.HEADER_SIZE - self.header.zstd_dictionary_length_bytes
        )
        compressed_buf = self.fh.read(compressed_length_bytes)
        ctx = zstandard.ZstdDecompressor(dict_data=dict_data)

        with ctx.stream_reader(compressed_buf) as reader:
            while True:
                try:
                    file = c_plocate.file(reader)
                    yield file.path.decode()
                except EOFError:
                    return

    def filename_index(self) -> bytes:
        self.fh.seek(self.header.filename_index_offset_bytes)
        num_docids = self.header.num_docids
        filename_index_size = num_docids * self.DOCID_SIZE_BYTES
        return self.fh.read(filename_index_size)

    def hashtable(self) -> bytes:
        self.fh.seek(self.header.hash_table_offset_bytes)
        hashtable_size = (self.header.hashtable_size + self.NUM_OVERFLOW_SLOTS + 1) * self.TRIGRAM_SIZE_BYTES
        return self.fh.read(hashtable_size)
