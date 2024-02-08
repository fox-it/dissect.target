from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.locate.mlocate import MLocateFile
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.locate.locate import BaseLocatePlugin

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
