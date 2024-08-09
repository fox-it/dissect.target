from typing import Any, Iterator, Union

from flow.record.fieldtypes.net import IPAddress

from dissect.target.helpers.record import (
    MacInterfaceRecord,
    UnixInterfaceRecord,
    WindowsInterfaceRecord,
)
from dissect.target.plugin import Plugin, export

InterfaceRecord = Union[UnixInterfaceRecord, WindowsInterfaceRecord, MacInterfaceRecord]


class NetworkPlugin(Plugin):
    __namespace__ = "network"
    _interface_list: list = None

    def check_compatible(self) -> None:
        pass

    def _interfaces(self) -> Iterator[InterfaceRecord]:
        yield from ()

    def _get_record_type(self, field_name: str) -> Iterator[Any]:
        for record in self.interfaces():
            if (output := getattr(record, field_name, None)) is None:
                continue

            if isinstance(output, list):
                yield from output
            else:
                yield output

    @export(record=InterfaceRecord)
    def interfaces(self) -> Iterator[InterfaceRecord]:
        # Only search for the interfaces once
        if self._interface_list is None:
            self._interface_list = list(self._interfaces)

        yield from self._interface_list

    @export
    def ips(self) -> list[IPAddress]:
        return list(self._get_record_type("ip"))

    @export
    def gateways(self) -> list[IPAddress]:
        return list(self._get_record_type("gateway"))

    @export
    def macs(self) -> list[str]:
        return list(self._get_record_type("mac"))

    @export
    def dns(self) -> list[str]:
        return list(self._get_record_type("dns"))
