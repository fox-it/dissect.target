from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import BinaryIO, Iterable, Iterator

from dissect.cstruct import cstruct
from dissect.util.ts import from_unix

# Resources: https://linux.die.net/man/5/locate.db
mlocate_def = """
#define MAGIC 0x006d6c6f63617465             /* b'/x00mlocate' */

struct header_config {
    int32 conf_size;
    int8 version;                            /* file format version */
    int8 require_visibility;
    int8 pad[2];                             /* 32-bit total alignment */
    char root_database;
    char config_block[conf_size];
    int8 pad;
};

enum DBE_TYPE: uint8 {                       /* database entry type */
    FILE         = 0x0,                      /* file */
    DIRECTORY    = 0x1,                      /* directory */
    END          = 0x2                       /* end of directory */
};

struct directory_entry {
    /* time is the 'maximum of st_ctime and
       st_mtime of the directory' according to docs */
    int64 time_seconds;
    int32 time_nanoseconds;
    int32 padding;
    char path[];
};

struct entry {
    char path[];
};
"""

c_mlocate = cstruct(endian=">")
c_mlocate.load(mlocate_def)


@dataclass
class MLocate:
    ts: datetime
    ts_ns: int
    parent: str
    path: Path
    dbe_type: str


class MLocateFile:
    """mlocate file parser

    Resources:
        - https://manpages.debian.org/testing/mlocate/mlocate.db.5.en.html
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        magic = int.from_bytes(self.fh.read(8), byteorder="big")
        if magic != c_mlocate.MAGIC:
            raise ValueError(f"Invalid mlocate file magic. Expected b'x00mlocate', got {magic}")

        self.header = c_mlocate.header_config(self.fh)

    def _parse_directory_entries(self) -> Iterator[str, c_mlocate.entry]:
        while (dbe_type := c_mlocate.DBE_TYPE(self.fh)) != c_mlocate.DBE_TYPE.END:
            entry = c_mlocate.entry(self.fh)
            dbe_type = "file" if dbe_type == c_mlocate.DBE_TYPE.FILE else "directory"

            yield dbe_type, entry

    def __iter__(self) -> Iterable[MLocateFile]:
        while True:
            try:
                directory_entry = c_mlocate.directory_entry(self.fh)
                parent = directory_entry.path.decode()

                for dbe_type, file_entry in self._parse_directory_entries():
                    file_path = file_entry.path.decode()

                    yield MLocate(
                        ts=from_unix(directory_entry.time_seconds),
                        ts_ns=directory_entry.time_nanoseconds,
                        parent=parent,
                        path=file_path,
                        dbe_type=dbe_type,
                    )
            except EOFError:
                return
