from __future__ import annotations

from typing import Any, Iterator, Union

from flow.record.fieldtypes.net import IPAddress, IPNetwork
from flow.record.fieldtypes.net.ipv4 import Address, addr_long, addr_str, mask_to_bits

from dissect.target.helpers.record import (
    MacInterfaceRecord,
    UnixInterfaceRecord,
    WindowsInterfaceRecord,
)
from dissect.target.plugin import Plugin, export, internal
from dissect.target.target import Target

InterfaceRecord = Union[UnixInterfaceRecord, WindowsInterfaceRecord, MacInterfaceRecord]


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
        """Yield interfaces."""
        # Only search for the interfaces once
        if self._interface_list is None:
            self._interface_list = list(self._interfaces())

        yield from self._interface_list

    @export
    def ips(self) -> list[IPAddress]:
        """Return IP addresses as list of :class:`IPAddress`."""
        return list(set(self._get_record_type("ip")))

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
        for interface in self.interfaces():
            if ip_addr in interface.ip:
                yield interface

    @internal
    def with_mac(self, mac: str) -> Iterator[InterfaceRecord]:
        for interface in self.interfaces():
            if mac in interface.mac:
                yield interface

    @internal
    def in_cidr(self, cidr: str) -> Iterator[InterfaceRecord]:
        cidr = IPNetwork(cidr)
        for interface in self.interfaces():
            if any(ip_addr in cidr for ip_addr in interface.ip):
                yield interface

    def calculate_network(self, ips: int | Address, subnets: int | Address) -> Iterator[str]:
        for ip, subnet_mask in zip(ips, subnets):
            subnet_mask_int = addr_long(subnet_mask)
            cidr = mask_to_bits(subnet_mask_int)
            network_address = addr_str(addr_long(ip) & subnet_mask_int)
            yield f"{network_address}/{cidr}"
