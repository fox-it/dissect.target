from functools import lru_cache
from typing import Iterator, Union

from dissect.target.helpers.record import (
    MacInterfaceRecord,
    TargetRecordDescriptor,
    UnixInterfaceRecord,
    WindowsInterfaceRecord,
)
from dissect.target.plugin import Plugin, Record, export, internal
from dissect.target.target import Target

# Using this notation as it didn't like the pipe symbol
InterfaceRecord = Union[UnixInterfaceRecord, WindowsInterfaceRecord, MacInterfaceRecord]


@lru_cache
def create_record(record: InterfaceRecord, name: str) -> Record:
    """Create a new record using the `record` name as its base.

    Also retrieves the typename from the record, so everything has the correct one.
    """
    record_descriptor = f"{record._desc.name}/{name}"
    field_type = record._desc.fields.get(name)
    field_type = field_type.typename if field_type else "string"

    record_fields = [
        ("string", "source"),
        (field_type, name),
    ]

    return TargetRecordDescriptor(record_descriptor, record_fields)


class NetworkPlugin(Plugin):
    __namespace__ = "network"

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self) -> None:
        pass

    @internal
    def find_interfaces(self) -> list[InterfaceRecord]:
        yield from ()

    def _get_record_type(self, field_name: str) -> Iterator[Record]:
        for record in self.find_interfaces():
            type_record = create_record(record, field_name)
            yield type_record(
                source=record.source,
                **{
                    field_name: getattr(record, field_name, None),
                },
                _target=self.target,
            )

    @export(output="record", export=InterfaceRecord)
    def interfaces(self) -> Iterator[InterfaceRecord]:
        yield from self.find_interfaces()

    @export(output="record", export=Record)
    def ips(self) -> Iterator[Record]:
        yield from self._get_record_type("ip")

    @export(output="record", export=Record)
    def gateways(self) -> Iterator[Record]:
        yield from self._get_record_type("gateway")

    @export(output="record", export=Record)
    def macs(self) -> Iterator[Record]:
        yield from self._get_record_type("mac")

    @export(output="record", export=Record)
    def dns(self) -> Iterator[Record]:
        yield from self._get_record_type("dns")
