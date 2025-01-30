from typing import Callable, Generator, Iterator, Union

from flow.record import GroupedRecord

from dissect.target import plugin
from dissect.target.exceptions import UnsupportedPluginError
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
        if not self.target._os_plugin:
            raise UnsupportedPluginError("No operating system detected on target")

    @plugin.export(record=OSInfoRecord)
    def osinfo(self) -> Iterator[Union[OSInfoRecord, GroupedRecord]]:
        """Yield grouped records with target OS info."""
        for os_func in self.target._os.__functions__:
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
