import csv
import gzip
from typing import Iterator

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

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

    def __init__(self, target):
        super().__init__(target)
        self.open_handles_file = target.fs.path("$metadata$/open_handles.csv.gz")

    def check_compatible(self) -> bool:
        return self.open_handles_file.exists()

    @export(record=AcquireOpenHandlesRecord)
    def acquire_handles(self) -> Iterator[AcquireOpenHandlesRecord]:
        """Return open handles collected by Acquire.

        An Acquire file container contains an open handles csv when the handles module was used. The content of this csv
        file is returned.
        """
        with self.open_handles_file.open() as fh:
            for row in csv.DictReader(gzip.open(fh, "rt")):
                yield AcquireOpenHandlesRecord(_target=self.target, **row)
