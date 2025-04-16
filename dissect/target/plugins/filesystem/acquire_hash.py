from __future__ import annotations

import csv
import gzip
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

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

    def __init__(self, target: Target):
        super().__init__(target)
        self.hash_file = target.fs.path("$metadata$/file-hashes.csv.gz")

    def check_compatible(self) -> None:
        if not self.hash_file.exists():
            raise UnsupportedPluginError("No hash file found")

    @export(record=AcquireHashRecord)
    def acquire_hashes(self) -> Iterator[AcquireHashRecord]:
        """Return file hashes collected by Acquire.

        An Acquire file container contains a file hashes csv when the hashes module was used. The content of this csv
        file is returned.
        """

        with self.hash_file.open() as fh, gzip.open(fh, "rt") as gz_fh:
            for row in csv.DictReader(gz_fh):
                yield AcquireHashRecord(
                    path=self.target.fs.path(row["path"]),
                    filesize=row["file-size"],
                    digest=(row["md5"] or None, row["sha1"] or None, row["sha256"] or None),
                    _target=self.target,
                )
