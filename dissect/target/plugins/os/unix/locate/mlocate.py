from typing import Iterator, Union

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.locate.mlocate import (
    MLocateDirectory,
    MLocateEntry,
    MLocateFileParser,
)
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.locate.locate import BaseLocatePlugin

MLocateDirectoryRecord = TargetRecordDescriptor(
    "linux/locate/mlocate_directory",
    [
        ("datetime", "ts"),
        ("string", "path"),
        ("string", "source"),
    ],
)

MLocateEntryRecord = TargetRecordDescriptor(
    "linux/locate/mlocate_entry",
    [
        ("string", "path"),
        ("string", "type"),
        ("string", "source"),
    ],
)

MLocateRecord = Union[
    MLocateEntryRecord,
    MLocateDirectoryRecord,
]


class MLocatePlugin(BaseLocatePlugin):
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
        mlocate_file = MLocateFileParser(mlocate_fh)

        for item in mlocate_file:
            if isinstance(item, MLocateDirectory):
                yield MLocateDirectoryRecord(ts=item.ts, path=item.path, source=self.path, _target=self.target)
            elif isinstance(item, MLocateEntry):
                yield MLocateEntryRecord(path=item.path, type=item.dbe_type, source=self.path, _target=self.target)
