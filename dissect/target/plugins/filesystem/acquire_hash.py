import csv
import gzip

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

AcquireHashRecord = TargetRecordDescriptor(
    "filesystem/acquire_hash",
    [
        ("path", "path"),
        ("filesize", "filesize"),
        ("digest", "digest"),
    ],
)


class AcquireHashPlugin(Plugin):
    """Plugin to return file hashes collected by Acquire."""

    def __init__(self, target):
        super().__init__(target)
        self.hash_file = target.fs.path("$metadata$/file-hashes.csv.gz")

    def check_compatible(self) -> None:
        if not self.hash_file.exists():
            raise UnsupportedPluginError("No hash file found")

    @export(record=AcquireHashRecord)
    def acquire_hashes(self):
        """Return file hashes collected by Acquire.

        An Acquire file container contains a file hashes csv when the hashes module was used. The content of this csv
        file is returned.
        """

        with self.hash_file.open() as fh:
            for row in csv.DictReader(gzip.open(fh, "rt")):
                yield AcquireHashRecord(
                    path=self.target.fs.path((row["path"])),
                    filesize=row["file-size"],
                    digest=(row["md5"] or None, row["sha1"] or None, row["sha256"] or None),
                    _target=self.target,
                )
