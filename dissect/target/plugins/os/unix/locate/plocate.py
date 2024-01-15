from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.locate.plocate import PLocateFileParser
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.unix.locate.locate import BaseLocatePlugin

try:
    import zstandard  # noqa

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

PLocateRecord = TargetRecordDescriptor(
    "linux/locate/plocate",
    [
        ("string", "path"),
        ("string", "source"),
    ],
)


class PLocatePlugin(BaseLocatePlugin):
    __namespace__ = "plocate"

    path = "/var/lib/plocate/plocate.db"

    def check_compatible(self) -> None:
        if not self.target.fs.path(self.path).exists():
            raise UnsupportedPluginError(f"No plocate.db file found at {self.path}")

        if not HAS_ZSTD:
            raise RuntimeError("Please install `python-zstandard` or `pip install zstandard` to use the PLocatePlugin")

    @export(record=PLocateRecord)
    def locate(self) -> PLocateRecord:
        """Yield file and directory names from the plocate.db.

        ``plocate`` is the default package on Ubuntu 22 and newer to locate files.
        It replaces ``mlocate`` and GNU ``locate``.

        Resources:
            - https://manpages.debian.org/testing/plocate/plocate.1.en.html
            - https://git.sesse.net/?p=plocate
        """
        plocate_fh = self.target.fs.path(self.path).open()
        plocate_file = PLocateFileParser(plocate_fh)

        for path in plocate_file.paths():
            yield PLocateRecord(path=path, source=self.path)
