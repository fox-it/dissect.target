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

AcquireOpenHandlesRecord = TargetRecordDescriptor(
    "filesystem/acquire_open_handles",
    [
        ("path", "name"),
        ("string", "handle_type"),
        ("string", "object"),
        ("varint", "unique_process_id"),
        ("varint", "handle_value"),
        ("varint", "granted_access"),
        ("varint", "creator_back_trace_index"),
        ("varint", "object_type_index"),
        ("varint", "handle_attributes"),
        ("varint", "reserved"),
    ],
)

AcquireHashRecord = TargetRecordDescriptor(
    "filesystem/acquire_hash",
    [
        ("path", "path"),
        ("filesize", "filesize"),
        ("digest", "digest"),
    ],
)


class AcquirePlugin(Plugin):
    """Returns records from data collected by Acquire."""

    __namespace__ = "acquire"

    def __init__(self, target: Target):
        super().__init__(target)
        self.hash_file = target.fs.path("$metadata$/file-hashes.csv.gz")
        self.open_handles_file = target.fs.path("$metadata$/open_handles.csv.gz")

    def check_compatible(self) -> None:
        if not self.hash_file.exists() and not self.open_handles_file.exists():
            raise UnsupportedPluginError("No hash file or open handles found")

    @export(record=AcquireHashRecord)
    def hashes(self) -> Iterator[AcquireHashRecord]:
        """Return file hashes collected by Acquire.

        An Acquire file container contains a file hashes csv when the hashes module was used. The content of this csv
        file is returned.
        """
        if self.hash_file.exists():
            with self.hash_file.open() as fh, gzip.open(fh, "rt") as gz_fh:
                for row in csv.DictReader(gz_fh):
                    yield AcquireHashRecord(
                        path=self.target.fs.path(row["path"]),
                        filesize=row["file-size"],
                        digest=(row["md5"] or None, row["sha1"] or None, row["sha256"] or None),
                        _target=self.target,
                    )

    @export(record=AcquireOpenHandlesRecord)
    def handles(self) -> Iterator[AcquireOpenHandlesRecord]:
        """Return open handles collected by Acquire.

        An Acquire file container contains an open handles csv when the handles module was used. The content of this csv
        file is returned.
        """
        if self.open_handles_file.exists():
            with self.open_handles_file.open() as fh, gzip.open(fh, "rt") as gz_fh:
                for row in csv.DictReader(gz_fh):
                    if name := row.get("name"):
                        row.update({"name": self.target.fs.path(name)})
                    yield AcquireOpenHandlesRecord(**row, _target=self.target)
