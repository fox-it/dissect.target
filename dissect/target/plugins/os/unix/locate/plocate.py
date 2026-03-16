from __future__ import annotations

import sys
from typing import TYPE_CHECKING, BinaryIO

from dissect.cstruct import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.locate.locate import BaseLocatePlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

try:
    if sys.version_info >= (3, 14):
        from compression import zstd  # novermin
    else:
        from backports import zstd

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

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
    uint32_t max_version;   // Nominally 1 or 2, but can be increased if more features are added in a backward-compatible way.
    uint32_t zstd_dictionary_length_bytes;
    uint64_t zstd_dictionary_offset_bytes;

    /* Only if max_version >= 2, and only relevant for updatedb. */
    uint64_t directory_data_length_bytes;
    uint64_t directory_data_offset_bytes;
    uint64_t next_zstd_dictionary_length_bytes;
    uint64_t next_zstd_dictionary_offset_bytes;
    uint64_t conf_block_length_bytes;
    uint64_t conf_block_offset_bytes;

    // Only if max_version >= 2.
    uint8_t check_visibility;
    char padding[7];                         /* padding for alignment */
};
"""  # noqa : E501

PLocateRecord = TargetRecordDescriptor(
    "linux/locate/plocate",
    [
        ("path", "path"),
        ("path", "source"),
    ],
)

c_plocate = cstruct().load(plocate_def)


class PLocateFile:
    """Parser for plocate files.

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

    References:
        - https://git.sesse.net/?p=plocate
    """

    HEADER_SIZE = 0x70  # 0x8 bytes magic + 0x68 bytes header
    NUM_OVERFLOW_SLOTS = 16
    TRIGRAM_SIZE_BYTES = 16

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        magic = int.from_bytes(self.fh.read(8), byteorder="big")
        if magic != c_plocate.MAGIC:
            raise ValueError(f"Invalid plocate file magic. Expected b'/x00plocate', got {magic}")

        self.header = c_plocate.header(self.fh)
        self.zstd_dict = None

        if self.header.zstd_dictionary_offset_bytes:
            self.zstd_dict = zstd.ZstdDict(self.fh.read(self.header.zstd_dictionary_length_bytes))

        self.compressed_length_bytes = (
            self.header.filename_index_offset_bytes - self.HEADER_SIZE - self.header.zstd_dictionary_length_bytes
        )

    def __iter__(self) -> Iterator[str]:
        offsets = self.filename_index()
        for i in range(self.header.num_docids):
            self.fh.seek(offsets[i])
            block = zstd.decompress(self.fh.read(offsets[i + 1] - offsets[i]), zstd_dict=self.zstd_dict)
            for path in block.split(b"\x00"):
                yield path.decode(errors="surrogateescape")

    def filename_index(self) -> list[int]:
        """Return the filename index of the plocate.db file."""
        self.fh.seek(self.header.filename_index_offset_bytes)
        return c_plocate.uint64[self.header.num_docids + 1](self.fh)

    def hashtable(self) -> bytes:
        """Return the hashtable of the plocate.db file."""
        self.fh.seek(self.header.hash_table_offset_bytes)
        hashtable_size = (self.header.hashtable_size + self.NUM_OVERFLOW_SLOTS + 1) * self.TRIGRAM_SIZE_BYTES
        return self.fh.read(hashtable_size)


class PLocatePlugin(BaseLocatePlugin):
    """Unix plocate plugin."""

    __namespace__ = "plocate"

    path = "/var/lib/plocate/plocate.db"

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.path).exists():
            raise UnsupportedPluginError(f"No plocate.db file found at {self.path}")

        if not HAS_ZSTD:
            raise UnsupportedPluginError(
                "Required dependency 'backports.zstd' is missing, install with `pip install backports.zstd` to use the PLocatePlugin"  # noqa: E501
            )

    @export(record=PLocateRecord)
    def locate(self) -> Iterator[PLocateRecord]:
        """Yield file and directory names from the plocate.db.

        ``plocate`` is the default package on Ubuntu 22 and newer to locate files.
        It replaces ``mlocate`` and GNU ``locate``.

        References:
            - https://manpages.debian.org/testing/plocate/plocate.1.en.html
            - https://git.sesse.net/?p=plocate
        """
        plocate = self.target.fs.path(self.path)
        plocate_file = PLocateFile(plocate.open())

        for path in plocate_file:
            yield PLocateRecord(
                path=self.target.fs.path(path),
                source=self.path,
            )
