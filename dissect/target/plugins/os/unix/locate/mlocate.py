from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, BinaryIO

from dissect.cstruct import cstruct
from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.locate.locate import BaseLocatePlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

# Resources: https://linux.die.net/man/5/locate.db
mlocate_def = """
#define MAGIC 0x006d6c6f63617465             /* b'/x00mlocate' */

struct header_config {
    int32 conf_size;
    int8 version;                            /* file format version */
    int8 require_visibility;
    int8 pad0[2];                             /* 32-bit total alignment */
    char root_database;
    char config_block[conf_size];
    int8 pad1;
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


@dataclass
class MLocate:
    ts: datetime
    ts_ns: int
    parent: str
    path: str
    dbe_type: str


MLocateRecord = TargetRecordDescriptor(
    "linux/locate/mlocate",
    [
        ("datetime", "ts"),
        ("varint", "ts_ns"),
        ("path", "parent"),
        ("path", "path"),
        ("string", "type"),
        ("string", "source"),
    ],
)

c_mlocate = cstruct(endian=">").load(mlocate_def)


class MLocateFile:
    """Parser for mlocate files.

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

    def __iter__(self) -> Iterator[MLocateFile]:
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
            except EOFError:  # noqa: PERF203
                return


class MLocatePlugin(BaseLocatePlugin):
    """Unix mlocate plugin."""

    __namespace__ = "mlocate"

    path = "/var/lib/mlocate/mlocate.db"

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.path).exists():
            raise UnsupportedPluginError(f"No mlocate.db file found at {self.path}")

    @export(record=MLocateRecord)
    def locate(self) -> Iterator[MLocateRecord]:
        """Yield file and directory names from mlocate.db file.

        ``mlocate`` is a new implementation of GNU locate,
        but has been deprecated since Ubuntu 22.

        Resources:
            - https://manpages.debian.org/testing/mlocate/mlocate.db.5.en.html
        """
        mlocate_fh = self.target.fs.path(self.path).open()
        mlocate_file = MLocateFile(mlocate_fh)

        for item in mlocate_file:
            parent = self.target.fs.path(item.parent)
            yield MLocateRecord(
                ts=item.ts,
                ts_ns=item.ts_ns,
                parent=parent,
                path=parent.joinpath(item.path),
                type=item.dbe_type,
                source=self.path,
                _target=self.target,
            )
