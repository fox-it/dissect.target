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


class OpenHandlesPlugin(Plugin):
    """Plugin to return open file handles collected by Acquire."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.open_handles_file = target.fs.path("$metadata$/open_handles.csv.gz")

    def check_compatible(self) -> None:
        if not self.open_handles_file.exists():
            raise UnsupportedPluginError("No open handles found")

    @export(record=AcquireOpenHandlesRecord)
    def acquire_handles(self) -> Iterator[AcquireOpenHandlesRecord]:
        """Return open handles collected by Acquire.

        An Acquire file container contains an open handles csv when the handles module was used. The content of this csv
        file is returned.
        """
        with self.open_handles_file.open() as fh, gzip.open(fh, "rt") as gz_fh:
            for row in csv.DictReader(gz_fh):
                if name := row.get("name"):
                    row.update({"name": self.target.fs.path(name)})
                yield AcquireOpenHandlesRecord(_target=self.target, **row)
