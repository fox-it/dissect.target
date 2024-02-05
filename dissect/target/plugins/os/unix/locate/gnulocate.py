from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.locate.gnulocate import GNULocateFile
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.locate.locate import BaseLocatePlugin

GNULocateRecord = TargetRecordDescriptor(
    "linux/locate/gnulocate",
    [
        ("path", "path"),
        ("string", "source"),
    ],
)


class GNULocatePlugin(BaseLocatePlugin):
    __namespace__ = "gnulocate"

    path = "/var/cache/locate/locatedb"

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.path).exists():
            raise UnsupportedPluginError(f"No locatedb file found at {self.path}")

    @export(record=GNULocateRecord)
    def locate(self) -> GNULocateRecord:
        """Yield file and directory names from GNU findutils' locatedb file.

        Resources:
            - https://manpages.debian.org/testing/locate/locatedb.5.en.html
        """
        locate_fh = self.target.fs.path(self.path).open()
        locate_file = GNULocateFile(locate_fh)

        for path in locate_file:
            yield GNULocateRecord(path=self.target.fs.path(path), source=self.path)
