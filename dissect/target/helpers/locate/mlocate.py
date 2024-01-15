import os.path
from typing import IO, Iterator, Union

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

struct directory {
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


class MLocateDirectory:
    def __init__(self, time_seconds, path):
        self.ts = from_unix(time_seconds)
        self.path = path


class MLocateEntry:
    def __init__(self, path, dbe_type):
        self.path = path
        self.dbe_type = dbe_type


class MLocateFileParser:
    """mlocate file parser

    Resources:
        - https://manpages.debian.org/testing/mlocate/mlocate.db.5.en.html
    """

    def __init__(self, file_handler: IO):
        self.fh = file_handler

        magic = int.from_bytes(self.fh.read(8), byteorder="big")
        if magic != c_mlocate.MAGIC:
            raise ValueError("is not a valid mlocate file")

        self.header = c_mlocate.header_config(self.fh)

    def _parse_directory_entries(self) -> Iterator:
        while True:
            dbe_type = c_mlocate.DBE_TYPE(self.fh)
            if dbe_type == c_mlocate.DBE_TYPE.END:
                break

            entry = c_mlocate.entry(self.fh)
            dbe_type = "file" if dbe_type == c_mlocate.DBE_TYPE.FILE else "directory"
            yield dbe_type, entry

    def __iter__(self) -> Iterator[Union[MLocateEntry, MLocateEntry]]:
        while True:
            try:
                directory = c_mlocate.directory(self.fh)
                directory_path = directory.path.decode()
            except EOFError:
                self.fh.close()
                return

            yield MLocateDirectory(time_seconds=directory.time_seconds, path=directory.path)

            for dbe_type, entry in self._parse_directory_entries():
                entry = entry.path.decode()
                yield MLocateEntry(path=os.path.join(directory_path, entry), dbe_type=dbe_type)
