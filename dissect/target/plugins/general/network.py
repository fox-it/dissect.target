from typing import Any, Iterator, Union

from flow.record.fieldtypes.net import IPAddress

from dissect.target.helpers.record import (
    MacInterfaceRecord,
    UnixInterfaceRecord,
    WindowsInterfaceRecord,
)
from dissect.target.plugin import Plugin, export, internal

InterfaceRecord = Union[UnixInterfaceRecord, WindowsInterfaceRecord, MacInterfaceRecord]


class NetworkPlugin(Plugin):
    __namespace__ = "network"

    def check_compatible(self) -> None:
        pass

    @internal
    def find_interfaces(self) -> list[InterfaceRecord]:
        yield from ()

    def _get_record_type(self, field_name: str) -> list[Any]:
        output_list = []
        for record in self.find_interfaces():
            if output := getattr(record, field_name, None):
                output_list.append(output)
        return output_list

    @export(record=InterfaceRecord)
    def interfaces(self) -> Iterator[InterfaceRecord]:
        yield from self.find_interfaces()

    @export
    def ips(self) -> list[IPAddress]:
        return self._get_record_type("ip")

    @export
    def gateways(self) -> list[IPAddress]:
        return self._get_record_type("gateway")

    @export
    def macs(self) -> list[str]:
        return self._get_record_type("mac")

    @export
    def dns(self) -> list[str]:
        return self._get_record_type("dns")
