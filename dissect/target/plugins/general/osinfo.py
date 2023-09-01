from typing import Callable, Generator, Iterator, Union

from flow.record import GroupedRecord

from dissect.target import plugin
from dissect.target.helpers.record import TargetRecordDescriptor

OSInfoRecord = TargetRecordDescriptor(
    "generic/osinfo",
    [
        ("string", "name"),
        ("string", "value"),
    ],
)


class OSInfoPlugin(plugin.Plugin):
    """Convenience plugin that wraps _os.* functions in records."""

    def check_compatible(self) -> None:
        pass

    @plugin.export(record=OSInfoRecord)
    def osinfo(self) -> Iterator[Union[OSInfoRecord, GroupedRecord]]:
        for os_func in self.target._os.__functions__:
            if os_func in ["is_compatible", "get_all_records"]:
                continue
            value = getattr(self.target._os, os_func)
            record = OSInfoRecord(name=os_func, value=None, _target=self.target)
            if isinstance(value, Callable) and isinstance(subrecords := value(), Generator):
                try:
                    yield GroupedRecord("generic/osinfo/grouped", [record] + list(subrecords))
                except Exception:
                    # Ignore exceptions triggered by functions
                    # that cannot be executed in this context
                    continue
            else:
                record.value = value
                yield record
