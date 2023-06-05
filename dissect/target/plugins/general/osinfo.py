from typing import Callable, Generator

from flow.record import GroupedRecord, Record

from dissect.target import plugin
from dissect.target.exceptions import PluginError
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

    def check_compatible(self) -> bool:
        return True

    @plugin.export(record=OSInfoRecord)
    def osinfo(self) -> Generator[Record, None, None]:
        for os_func in self.target._os.__functions__:
            if os_func in ["is_compatible", "get_all_records"]:
                continue
            value = getattr(self.target._os, os_func)
            record = OSInfoRecord(name=os_func, value=repr(value), _target=self.target)
            yield record
            if isinstance(value, Callable):
                try:
                    for subvalue in value():
                        yield GroupedRecord("generic/osinfo/grouped", [record, subvalue])
                except (PluginError, TypeError):
                    # Ignore exceptions triggered by functions
                    # that cannot be executed in this context
                    continue
