from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_interface
from itertools import chain
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from dissect.target.helpers import configutil
from dissect.target.helpers.record import UnixInterfaceRecord
from dissect.target.helpers.utils import to_list
from dissect.target.plugins.os.default.network import NetworkPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from ipaddress import IPv4Address, IPv4Interface, IPv6Address, IPv6Interface

    from dissect.target.target import Target, TargetPath

    NetAddress = IPv4Address | IPv6Address
    NetInterface = IPv4Interface | IPv6Interface


class LinuxNetworkPlugin(NetworkPlugin):
    """Linux network interface plugin."""

    def _interfaces(self) -> Iterator[UnixInterfaceRecord]:
        """Try all available network configuration managers and aggregate the results."""
        for manager_cls in MANAGERS:
            manager: LinuxNetworkConfigParser = manager_cls(self.target)
            yield from manager.interfaces()


VlanIdByInterface = dict[str, set[int]]


class LinuxNetworkConfigParser:
    def __init__(self, target: Target):
        self._target = target

    def _config_files(self, config_paths: list[str], glob: str) -> list[TargetPath]:
        """Returns all configuration files in config_paths matching the given extension."""
        all_files = []
        for config_path in config_paths:
            paths = self._target.fs.path(config_path).glob(glob)
            all_files.extend(config_file for config_file in paths if config_file.is_file())

        return sorted(all_files, key=lambda p: p.stem)

    def interfaces(self) -> Iterator[UnixInterfaceRecord]:
        """Parse network interfaces from configuration files."""
        yield from ()


class NetworkManagerConfigParser(LinuxNetworkConfigParser):
    """NetworkManager configuration parser.

    NetworkManager configuration files are generally in an INI-like format.
    Note that Red Hat and Fedora deprecated ifcfg files.
    Documentation: https://networkmanager.dev/docs/api/latest/nm-settings-keyfile.html
    """

    config_paths: tuple[str, ...] = (
        "/etc/NetworkManager/system-connections/",
        "/usr/lib/NetworkManager/system-connections/",
        "/run/NetworkManager/system-connections/",
    )

    @dataclass
    class ParserContext:
        source: str
        uuid: str | None = None
        last_connected: datetime | None = None
        name: str | None = None
        mac_address: str | None = None
        type: str = ""
        dns: set[NetAddress] = field(default_factory=set)
        ip_interfaces: set[NetInterface] = field(default_factory=set)
        gateways: set[NetAddress] = field(default_factory=set)
        dhcp_ipv4: bool = False
        dhcp_ipv6: bool = False
        vlan: set[int] = field(default_factory=set)

        def to_record(self, target: Target) -> UnixInterfaceRecord:
            return UnixInterfaceRecord(
                name=self.name,
                type=self.type,
                enabled=None,
                cidr=self.ip_interfaces,
                gateway=list(self.gateways),
                dns=list(self.dns),
                mac=to_list(self.mac_address),
                source=self.source,
                dhcp_ipv4=self.dhcp_ipv4,
                dhcp_ipv6=self.dhcp_ipv6,
                last_connected=self.last_connected,
                vlan=list(self.vlan),
                configurator="NetworkManager",
                _target=target,
            )

    def interfaces(self) -> Iterator[UnixInterfaceRecord]:
        connections: list[NetworkManagerConfigParser.ParserContext] = []
        vlan_id_by_interface: VlanIdByInterface = {}

        for connection_file_path in self._config_files(self.config_paths, "*"):
            try:
                config = configutil.parse(connection_file_path, hint="ini")
                context = self.ParserContext(source=connection_file_path)
                common_section: dict[str, str] = config.get("connection", {})
                context.type = common_section.get("type", "")
                sub_type: dict[str, str] = config.get(context.type, {})

                if context.type == "vlan":
                    self._parse_vlan(sub_type, vlan_id_by_interface)
                    continue

                for ip_version in ["ipv4", "ipv6"]:
                    ip_section: dict[str, str] = config.get(ip_version, {})
                    for key, value in ip_section.items():
                        self._parse_ip_section_key(key, value, context, ip_version)

                context.name = common_section.get("interface-name")
                context.mac_address = sub_type.get("mac-address")
                context.uuid = common_section.get("uuid")
                context.source = str(connection_file_path)
                context.last_connected = self._parse_lastconnected(common_section.get("timestamp", ""))

                connections.append(context)

            except Exception as e:
                self._target.log.warning("Error parsing network config file %s", connection_file_path)
                self._target.log.debug("", exc_info=e)

        for connection in connections:
            vlan_ids_from_interface = vlan_id_by_interface.get(connection.name, set())
            connection.vlan.update(vlan_ids_from_interface)

            vlan_ids_from_uuid = vlan_id_by_interface.get(connection.uuid, set())
            connection.vlan.update(vlan_ids_from_uuid)

            yield connection.to_record(self._target)

    def _parse_route(self, route: str) -> NetAddress | None:
        """Parse a route and return gateway IP address."""
        if (elements := route.split(",")) and len(elements) > 1:
            return ip_address(elements[1])

        return None

    def _parse_lastconnected(self, last_connected: str) -> datetime | None:
        """Parse last connected timestamp."""
        if not last_connected:
            return None

        return datetime.fromtimestamp(int(last_connected), timezone.utc)

    def _parse_ip_section_key(
        self, key: str, value: str, context: ParserContext, ip_version: Literal["ipv4", "ipv6"]
    ) -> None:
        if not (trimmed := value.strip()):
            return

        if key == "dns":
            context.dns.update(ip_address(addr) for addr in trimmed.split(";") if addr)
        elif key.startswith("address"):
            # Undocumented: single gateway on address line. Observed when running:
            # nmcli connection add type ethernet ... ip4 192.168.2.138/24 gw4 192.168.2.1
            ip, *gateway = trimmed.split(",", 1)
            context.ip_interfaces.add(ip_interface(ip))
            if gateway:
                context.gateways.add(ip_address(gateway[0]))
        elif key.startswith("gateway"):
            context.gateways.add(ip_address(trimmed))
        elif key == "method":
            if ip_version == "ipv4":
                context.dhcp_ipv4 = trimmed == "auto"
            elif ip_version == "ipv6":
                context.dhcp_ipv6 = trimmed == "auto"
        elif key.startswith("route") and (gateway := self._parse_route(value)):
            context.gateways.add(gateway)

    def _parse_vlan(self, sub_type: dict[str, Any], vlan_id_by_interface: VlanIdByInterface) -> None:
        parent_interface = sub_type.get("parent")
        vlan_id = sub_type.get("id")
        if not parent_interface or not vlan_id:
            return

        ids = vlan_id_by_interface.setdefault(parent_interface, set())
        ids.add(int(vlan_id))


class SystemdNetworkConfigParser(LinuxNetworkConfigParser):
    """Systemd network configuration parser.

    Systemd network configuration files are generally in an INI-like format with some quirks.
    Note that drop-in directories are not yet supported.

    Documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html
    """

    collapsable_items: tuple[str, ...] = ("Match", "Network", "Link", "MACAddress", "Name", "Type")

    config_paths: tuple[str, ...] = (
        "/etc/systemd/network/",
        "/run/systemd/network/",
        "/usr/lib/systemd/network/",
        "/usr/local/lib/systemd/network/",
    )

    class DhcpConfig(NamedTuple):
        ipv4: bool
        ipv6: bool

    # Can be enclosed in brackets for IPv6. Can also have port, iface name, and SNI, which we ignore.
    # Example: [1111:2222::3333]:9953%ifname#example.com
    dns_ip_patttern = re.compile(
        r"(?P<withoutBrackets>(?:\d{1,3}\.){3}\d{1,3})|\[(?P<withBrackets>\[?[0-9a-fA-F:]+\]?)\]"
    )

    def interfaces(self) -> Iterator:
        virtual_networks = self._parse_virtual_networks()
        yield from self._parse_networks(virtual_networks)

    def _parse_virtual_networks(self) -> VlanIdByInterface:
        """Parse virtual network configurations from systemd network configuration files."""

        virtual_networks: VlanIdByInterface = {}
        for config_file in self._config_files(self.config_paths, "*.netdev"):
            try:
                virtual_network_config = configutil.parse(config_file, hint="systemd")
                net_dev_section: dict[str, str] = virtual_network_config.get("NetDev", {})
                if net_dev_section.get("Kind") != "vlan":
                    continue

                vlan_id = virtual_network_config.get("VLAN", {}).get("Id")
                if (name := net_dev_section.get("Name")) and vlan_id:
                    vlan_ids = virtual_networks.setdefault(name, set())
                    vlan_ids.add(int(vlan_id))
            except Exception as e:
                self._target.log.warning("Error parsing virtual network config file %s", config_file)
                self._target.log.debug("", exc_info=e)

        return virtual_networks

    def _parse_networks(self, virtual_networks: VlanIdByInterface) -> Iterator[UnixInterfaceRecord]:
        """Parse network configurations from systemd network configuration files."""
        for config_file in self._config_files(self.config_paths, "*.network"):
            try:
                config = configutil.parse(config_file, hint="systemd", collapse=self.collapsable_items)

                match_section: dict[str, str] = config.get("Match", {})
                network_section: dict[str, str] = config.get("Network", {})
                link_section: dict[str, str] = config.get("Link", {})

                ip_interfaces: set[NetInterface] = set()
                gateways: set[NetAddress] = set()
                dns: set[NetAddress] = set()
                mac_addresses: set[str] = set()

                if link_mac := link_section.get("MACAddress"):
                    mac_addresses.add(link_mac)
                mac_addresses.update(match_section.get("MACAddress", "").split())
                mac_addresses.update(match_section.get("PermanentMACAddress", "").split())

                dns_value = to_list(network_section.get("DNS", []))
                dns.update(self._parse_dns_ip(dns_ip) for dns_ip in dns_value)

                address_value = to_list(network_section.get("Address", []))
                ip_interfaces.update(ip_interface(addr) for addr in address_value)

                gateway_value = to_list(network_section.get("Gateway", []))
                gateways.update(ip_address(gateway) for gateway in gateway_value)

                vlan_ids: set[int] = set()
                vlan_names = to_list(network_section.get("VLAN", []))
                for vlan_name in vlan_names:
                    if ids := virtual_networks.get(vlan_name):
                        vlan_ids.update(ids)

                route_sections: list[dict[str, Any]] = config.get("Route", [])
                gateway_values = (to_list(route_section.get("Gateway", [])) for route_section in route_sections)
                gateways.update(filter(None, map(self._parse_gateway, chain.from_iterable(gateway_values))))

                dhcp_ipv4, dhcp_ipv6 = self._parse_dhcp(network_section.get("DHCP"))

                yield UnixInterfaceRecord(
                    name=match_section.get("Name"),
                    type=match_section.get("Type"),
                    enabled=None,  # Unknown, dependent on run-time state
                    cidr=ip_interfaces,
                    gateway=list(gateways),
                    dns=list(dns),
                    mac=list(mac_addresses),
                    source=str(config_file),
                    dhcp_ipv4=dhcp_ipv4,
                    dhcp_ipv6=dhcp_ipv6,
                    vlan=list(vlan_ids),
                    configurator="systemd-networkd",
                    _target=self._target,
                )
            except Exception as e:  # noqa: PERF203
                self._target.log.warning("Error parsing network config file %s", config_file)
                self._target.log.debug("", exc_info=e)

    def _parse_dns_ip(self, address: str) -> NetAddress:
        """Parse DNS address from systemd network configuration file.

        The optional brackets and port number make this hard to parse.
        See https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html and search for DNS.
        """

        if match := self.dns_ip_patttern.search(address):
            return ip_address(match.group("withoutBrackets") or match.group("withBrackets"))

        raise ValueError(f"Invalid DNS address format: {address}")

    def _parse_dhcp(self, value: str | None) -> DhcpConfig:
        """Parse DHCP value from systemd network configuration file to a named tuple (ipv4, ipv6)."""

        if value is None or value == "no":
            return self.DhcpConfig(ipv4=False, ipv6=False)
        if value == "yes":
            return self.DhcpConfig(ipv4=True, ipv6=True)
        if value == "ipv4":
            return self.DhcpConfig(ipv4=True, ipv6=False)
        if value == "ipv6":
            return self.DhcpConfig(ipv4=False, ipv6=True)

        raise ValueError(f"Invalid DHCP value: {value}")

    def _parse_gateway(self, value: str | None) -> NetAddress | None:
        if (not value) or (value in {"_dhcp4", "_ipv6ra"}):
            return None

        return ip_address(value)


MANAGERS = [NetworkManagerConfigParser, SystemdNetworkConfigParser]
