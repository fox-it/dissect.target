from __future__ import annotations

from typing import BinaryIO, Iterable

from dissect.cstruct import cstruct

gnulocate_def = """
#define MAGIC 0x004c4f43415445303200             /* b'/x00LOCATE02/x00' */

struct entry {
    int8 offset;
    char path[];
}
"""

c_gnulocate = cstruct()
c_gnulocate.load(gnulocate_def)


class GNULocateFile:
    """locate file parser

    Multiple formats exist for the locatedb file. This class only supports the most recent version ``LOCATE02``.

    The file is encoded with front compression (incremental encoding). This is a form of compression
    which takes a number of characters of the previous encoded entries. Entries are separated with a null byte.

    Resources:
        - https://manpages.ubuntu.com/manpages/trusty/en/man5/locatedb.5.html
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.count = 0
        self.previous_path = ""

        magic = int.from_bytes(self.fh.read(10), byteorder="big")
        if magic != c_gnulocate.MAGIC:
            raise ValueError(f"Invalid Locate file magic. Expected /x00LOCATE02/x00, got {magic}")

    def __iter__(self) -> Iterable[GNULocateFile]:
        try:
            while True:
                # NOTE: The offset could be negative, which indicates
                # that we decrease the number of characters of the previous path.
                entry = c_gnulocate.entry(self.fh)
                current_filepath_end = entry.path.decode(errors="backslashreplace")
                offset = entry.offset

                self.count += offset

                path = self.previous_path[0 : self.count] + current_filepath_end
                self.previous_path = path
                yield path
        except EOFError:
            return
