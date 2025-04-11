from __future__ import annotations

from operator import attrgetter
from typing import TYPE_CHECKING, Any, Callable, Union, get_args

from flow.record.fieldtypes.net import IPAddress, IPNetwork

from dissect.target.helpers.record import (
    MacOSInterfaceRecord,
    UnixInterfaceRecord,
    WindowsInterfaceRecord,
)
from dissect.target.plugin import Plugin, export, internal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target
InterfaceRecord = Union[UnixInterfaceRecord, WindowsInterfaceRecord, MacOSInterfaceRecord]


class NetworkPlugin(Plugin):
    """Generic implementation for network interfaces plugin."""

    __namespace__ = "network"

    def __init__(self, target: Target):
        super().__init__(target)
        self._interface_list: list[InterfaceRecord] | None = None

    def check_compatible(self) -> None:
        pass

    def _interfaces(self) -> Iterator[InterfaceRecord]:
        yield from ()

    def _get_record_type(self, field_name: str, func: Callable[[Any], Any] | None = None) -> Iterator[Any]:
        for record in self.interfaces():
            if (output := getattr(record, field_name, None)) is None:
                continue

            if not isinstance(output, list):
                output = [output]

            yield from (map(func, output) if func else output)

    @export(record=get_args(InterfaceRecord))
    def interfaces(self) -> Iterator[InterfaceRecord]:
        """Yield interfaces."""
        # Only search for the interfaces once
        if self._interface_list is None:
            self._interface_list = list(self._interfaces())

        yield from self._interface_list

    @export
    def ips(self) -> list[IPAddress]:
        """Return IP addresses as list of :class:`IPAddress`."""
        return list(set(self._get_record_type("cidr", attrgetter("ip"))))

    @export
    def gateways(self) -> list[IPAddress]:
        """Return gateways as list of :class:`IPAddress`."""
        return list(set(self._get_record_type("gateway")))

    @export
    def macs(self) -> list[str]:
        """Return MAC addresses as list of :class:`str`."""
        return list(set(self._get_record_type("mac")))

    @export
    def dns(self) -> list[str | IPAddress]:
        """Return DNS addresses as list of :class:`str`."""
        return list(set(self._get_record_type("dns")))

    @internal
    def with_ip(self, ip_addr: str) -> Iterator[InterfaceRecord]:
        """Yield all interfaces with the given IP address."""
        for interface in self.interfaces():
            if any(iface.ip == ip_addr for iface in interface.cidr):
                yield interface

    @internal
    def with_mac(self, mac: str) -> Iterator[InterfaceRecord]:
        """Yield all interfaces with the given full or partial MAC address."""
        for interface in self.interfaces():
            if mac in interface.mac:
                yield interface

    @internal
    def in_cidr(self, cidr: str) -> Iterator[InterfaceRecord]:
        """Yield all interfaces with IP addresses in the given CIDR range."""
        cidr = IPNetwork(cidr)
        for interface in self.interfaces():
            if any(iface.ip in cidr for iface in interface.cidr):
                yield interface
