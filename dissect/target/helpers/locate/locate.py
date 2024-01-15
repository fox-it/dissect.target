from typing import IO, Iterator

from dissect.cstruct import cstruct

locate_def = """
#define MAGIC 0x004c4f43415445303200             /* b'/x00LOCATE02/x00' */

struct file {
    char path_ending[];
}
"""

c_locate = cstruct()
c_locate.load(locate_def)


class LocateFileParser:
    """locate file parser

    Multiple formats exist for the locatedb file. This class only supports the most recent version ``LOCATE02``.

    The file is encoded with front compression (incremental encoding). This is a form of compression
    which takes a number of characters of the previous encoded entries. Entries are separated with a null byte.

    Resources:
        - https://manpages.ubuntu.com/manpages/trusty/en/man5/locatedb.5.html
    """

    def __init__(self, file_handler: IO):
        self.fh = file_handler
        self.fh.seek(0)

        magic = int.from_bytes(self.fh.read(10), byteorder="big")
        if magic != c_locate.MAGIC:
            raise ValueError("is not a valid locate file")

    def __iter__(self) -> Iterator[str]:
        count = 0
        previous_path = ""

        try:
            while True:
                # NOTE: The offset could be negative, which indicates that we
                # decrease the number of characters of the previous path.
                offset = int.from_bytes(self.fh.read(1), byteorder="big", signed=True)
                count += offset

                current_filepath_end = c_locate.file(self.fh).path_ending.decode()
                path = previous_path[0:count] + current_filepath_end
                yield path
                previous_path = path
        except EOFError:
            return
