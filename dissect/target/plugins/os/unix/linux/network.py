from __future__ import annotations

import re
from datetime import datetime, timezone
from ipaddress import ip_address, ip_interface
from typing import Iterator

from dissect.target import Target
from dissect.target.helpers import configutil
from dissect.target.helpers.record import UnixInterfaceRecord
from dissect.target.plugins.general.network import NetworkPlugin
from dissect.target.target import TargetPath


class LinuxNetworkPlugin(NetworkPlugin):
    """Linux network interface plugin."""

    def _interfaces(self) -> Iterator[UnixInterfaceRecord]:
        """Try all available network configuration managers and aggregate the results."""
        for manager_cls in MANAGERS:
            manager: LinuxConfigParser = manager_cls(self.target)
            yield from manager.interfaces()


class LinuxConfigParser:
    VlanIdByName = dict[str, int]

    def __init__(self, target: Target):
        self._target = target

    def _config_files(self, config_paths: list[str], glob: str) -> list[TargetPath]:
        """Yield all configuration files in config_paths matching the given extension."""
        all_files = []
        for config_path in config_paths:
            paths = self._target.fs.path(config_path).glob(glob)
            all_files.extend(config_file for config_file in paths if config_file.is_file())

        return sorted(all_files, key=lambda p: p.name)

    def interfaces(self) -> Iterator[UnixInterfaceRecord]:
        """Parse network interfaces from configuration files."""
        yield from ()


class NetworkManagerConfigParser(LinuxConfigParser):
    config_paths: list[str] = [
        "/etc/NetworkManager/system-connections/",
        "/usr/lib/NetworkManager/system-connections/",
        "/run/NetworkManager/system-connections/",
    ]

    def interfaces(self) -> Iterator[UnixInterfaceRecord]:
        connections: dict[str, dict] = {}
        vlan_id_by_interface: LinuxConfigParser.VlanIdByName = {}

        for connection_file_path in self._config_files(self.config_paths, "*"):
            try:
                connection = configutil.parse(connection_file_path, hint="ini")

                common_section: dict[str, str] = connection.get("connection", {})
                interface_type = common_section.get("type", "")
                sub_type: dict[str, str] = connection.get(interface_type, {})

                if interface_type == "vlan":
                    # Store vlan id by parent interface name
                    parent_interface = sub_type.get("parent", None)
                    vlan_id = sub_type.get("id", None)
                    if parent_interface and vlan_id:
                        vlan_id_by_interface[parent_interface] = int(vlan_id)
                    continue

                dns = set[ip_address]()
                ip_interfaces: set[ip_interface] = set()
                gateways: set[ip_address] = set()
                dhcp_settings: dict[str, str] = {"ipv4": "", "ipv6": ""}

                for ip_version in ["ipv4", "ipv6"]:
                    ip_section: dict[str, str] = connection.get(ip_version, {})
                    for key, value in ip_section.items():
                        # nmcli inserts a trailling semicolon
                        if key == "dns" and (stripped := value.rstrip(";")):
                            dns.update({ip_address(addr) for addr in stripped.split(";")})
                        elif key.startswith("address"):
                            # Undocumented: single gateway on address line. Observed when running:
                            # nmcli connection add type ethernet ... ip4 192.168.2.138/24 gw4 192.168.2.1
                            ip, *gateway = value.split(",", 1)
                            ip_interfaces.add(ip_interface(ip))
                            if gateway:
                                gateways.add(ip_address(gateway[0]))
                        elif key.startswith("gateway"):
                            gateways.add(ip_address(value))
                        elif key == "method":
                            dhcp_settings[ip_version] = value
                        elif key.startswith("route"):
                            if gateway := self._parse_route(value):
                                gateways.add(gateway)

                name = common_section.get("interface-name", None)
                mac_address = [sub_type.get("mac-address", "")] if sub_type.get("mac-address", "") else []
                connections[name] = {  # Store as dict to allow for clean updating with vlan
                    "source": str(connection_file_path),
                    "enabled": None,  # Stored in run-time state
                    "last_connected": self._parse_lastconnected(common_section.get("timestamp", "")),
                    "name": name,
                    "mac": mac_address,
                    "type": interface_type,
                    "dhcp_ipv4": dhcp_settings.get("ipv4", {}) == "auto",
                    "dhcp_ipv6": dhcp_settings.get("ipv6", {}) == "auto",
                    "dns": list(dns),
                    "ip": [interface.ip for interface in ip_interfaces],
                    "network": [interface.network for interface in ip_interfaces],
                    "gateway": list(gateways),
                    "configurator": "NetworkManager",
                }
            except Exception as e:
                self._target.log.warning("Error parsing network config file %s: %s", connection_file_path, e)

        for parent_interface_name, vlan_id in vlan_id_by_interface.items():
            if parent_connection := connections.get(parent_interface_name):
                parent_connection["vlan"] = {vlan_id}

        for connection in connections.values():
            yield UnixInterfaceRecord(**connection)

    def _parse_route(self, route: str) -> ip_address | None:
        """Parse a route and return gateway IP address."""
        if (elements := route.split(",")) and len(elements) > 1:
            return ip_address(elements[1])

        return None

    def _parse_lastconnected(self, value: str) -> datetime | None:
        """Parse last connected timestamp."""
        if not value:
            return None

        timestamp_int = int(value)
        return datetime.fromtimestamp(timestamp_int, timezone.utc)


class SystemdNetworkConfigParser(LinuxConfigParser):
    config_paths: list[str] = [
        "/etc/systemd/network/",
        "/run/systemd/network/",
        "/usr/lib/systemd/network/",
        "/usr/local/lib/systemd/network/",
    ]

    # Can be enclosed in brackets for IPv6. Can also have port, iface name, and SNI, which we ignore.
    # Example: [1111:2222::3333]:9953%ifname#example.com
    dns_ip_patttern = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})|\[(\[?[0-9a-fA-F:]+\]?)\]")

    def interfaces(self) -> Iterator:
        virtual_networks = self._parse_virtual_networks()
        yield from self._parse_networks(virtual_networks)

    def _parse_virtual_networks(self) -> LinuxConfigParser.VlanIdByName:
        """Parse virtual network configurations from systemd network configuration files."""

        virtual_networks: LinuxConfigParser.VlanIdByName = {}
        for config_file in self._config_files(self.config_paths, "*.netdev"):
            try:
                virtual_network_config = configutil.parse(config_file, hint="systemd")
                net_dev_section: dict[str, str] = virtual_network_config.get("NetDev", {})
                if net_dev_section.get("Kind") != "vlan":
                    continue

                vlan_id = virtual_network_config.get("VLAN", {}).get("Id")
                if (name := net_dev_section.get("Name")) and vlan_id:
                    virtual_networks[name] = int(vlan_id)
            except Exception as e:
                self._target.log.warning("Error parsing virtual network config file %s: %s", config_file, e)

        return virtual_networks

    def _parse_networks(self, virtual_networks: LinuxConfigParser.VlanIdByName) -> Iterator[UnixInterfaceRecord]:
        """Parse network configurations from systemd network configuration files."""
        for config_file in self._config_files(self.config_paths, "*.network"):
            try:
                config = configutil.parse(config_file, hint="systemd")

                match_section: dict[str, str] = config.get("Match", {})
                network_section: dict[str, str] = config.get("Network", {})
                link_section: dict[str, str] = config.get("Link", {})

                ip_interfaces: set[ip_interface] = set()
                gateways: set[ip_address] = set()
                dns: set[ip_address] = set()
                mac_addresses = set[str]()

                dhcp_ipv4, dhcp_ipv6 = self._parse_dhcp(network_section.get("DHCP"))
                if link_mac := link_section.get("MACAddress"):
                    mac_addresses.add(link_mac)
                if match_macs := match_section.get("MACAddress"):
                    mac_addresses.update(match_macs.split(" "))
                if permanent_macs := match_section.get("PermanentMACAddress"):
                    mac_addresses.update(permanent_macs.split(" "))

                if dns_value := network_section.get("DNS"):
                    if isinstance(dns_value, str):
                        dns_value = [dns_value]
                    dns.update({self._parse_dns_ip(dns_ip) for dns_ip in dns_value})

                if address_value := network_section.get("Address"):
                    if isinstance(address_value, str):
                        address_value = [address_value]
                    ip_interfaces.update({ip_interface(addr) for addr in address_value})

                if gateway_value := network_section.get("Gateway"):
                    if isinstance(gateway_value, str):
                        gateway_value = [gateway_value]
                    gateways.update({ip_address(gateway) for gateway in gateway_value})

                vlan_values = network_section.get("VLAN", [])
                vlan_ids = {
                    virtual_networks[vlan_name]
                    for vlan_name in ([vlan_values] if isinstance(vlan_values, str) else vlan_values)
                    if vlan_name in virtual_networks
                }

                # There are possibly multiple route sections, but they are collapsed into one by the parser.
                route_section = config.get("Route", {})
                gateway_values = route_section.get("Gateway", [])
                if isinstance(gateway_values, str):
                    gateway_values = [gateway_values]
                gateways.update(filter(None, map(self._parse_gateway, gateway_values)))

                yield UnixInterfaceRecord(
                    source=str(config_file),
                    type=match_section.get("Type", None),
                    enabled=None,  # Unknown, dependent on run-time state
                    dhcp_ipv4=dhcp_ipv4,
                    dhcp_ipv6=dhcp_ipv6,
                    name=match_section.get("Name", None),
                    dns=list(dns),
                    mac=list(mac_addresses),
                    ip=[interface.ip for interface in ip_interfaces],
                    network=[interface.network for interface in ip_interfaces],
                    gateway=list(gateways),
                    vlan=list(vlan_ids),
                    configurator="systemd-networkd",
                )
            except Exception as e:
                self._target.log.warning("Error parsing network config file %s: %s", config_file, e)

    def _parse_dns_ip(self, address: str) -> ip_address:
        """Parse DNS address from systemd network configuration file.

        See https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html DNS for details.
        """

        match = self.dns_ip_patttern.search(address)
        if match:
            return ip_address(match.group(1) or match.group(2))
        else:
            raise ValueError(f"Invalid DNS address format: {address}")

    def _parse_dhcp(self, value: str | None) -> tuple[bool, bool]:
        """Parse DHCP value from systemd network configuration file to a boolean tuple (ipv4, ipv6)."""

        if value is None or value == "no":
            return False, False
        elif value == "yes":
            return True, True
        elif value == "ipv4":
            return True, False
        elif value == "ipv6":
            return False, True
        else:
            raise ValueError(f"Invalid DHCP value: {value}")

    def _parse_gateway(self, value: str | None) -> ip_address | None:
        return None if not value or value in {"_dhcp4", "_ipv6ra"} else ip_address(value)


MANAGERS = [NetworkManagerConfigParser, SystemdNetworkConfigParser]
