from __future__ import annotations

import plistlib
from typing import Iterator

from dissect.target.helpers.record import MacInterfaceRecord
from dissect.target.plugin import internal
from dissect.target.plugins.general.network import NetworkPlugin


class MacNetworkPlugin(NetworkPlugin):
    SYSTEM = "/Library/Preferences/SystemConfiguration/preferences.plist"
    DHCP = "/private/var/db/dhcpclient/leases"
    plistlease = {}
    plistnetwork = {}

    def _plistlease(self) -> None:
        if (dhcp := self.target.fs.path(self.DHCP)).exists():
            for lease in dhcp.iterdir():
                if lease.is_file():
                    self.plistlease = plistlib.load(lease.open())

    def _plistnetwork(self) -> None:
        if (preferences := self.target.fs.path(self.SYSTEM)).exists():
            self.plistnetwork = plistlib.load(preferences.open())

    @internal
    def _interfaces(self) -> Iterator[MacInterfaceRecord]:
        if not self.plistlease:
            self._plistlease()

        if not self.plistnetwork:
            self._plistnetwork()

        dhcp_ip = self.plistlease.get("IPAddress")

        current_set = self.plistnetwork.get("CurrentSet")
        sets = self.plistnetwork.get("Sets", {})
        for name, _set in sets.items():
            if f"/Sets/{name}" == current_set:
                item = _set
                for key in ["Network", "Global", "IPv4", "ServiceOrder"]:
                    item = item.get(key, {})
                service_order = item
                break

        network = self.plistnetwork.get("NetworkServices", {})
        vlans = self.plistnetwork.get("VirtualNetworkInterfaces", {}).get("VLAN", {})
        vlan_lookup = {}
        for key, vlan in vlans.items():
            vlan_lookup[key] = vlan.get("Tag")

        for _id, interface in network.items():
            dns = set()
            gateways = set()
            proxies = set()
            ips = set()
            record = MacInterfaceRecord(_target=self.target)
            record.source = "NetworkServices"
            device = interface.get("Interface", {})
            record.name = device.get("DeviceName")
            record.type = device.get("Type")
            record.vlan = vlan_lookup.get(record.name)
            record.interface_service_order = service_order.index(_id) if _id in service_order else None
            try:
                record.enabled = not interface.get("__INACTIVE__", False)
                for setting, value in interface.get("Proxies", {}).items():
                    if setting.endswith("Proxy"):
                        proxies.add(value)
                record.proxy = proxies
                for addr in interface.get("DNS", {}).get("ServerAddresses", {}):
                    dns.add(addr)
                for addresses in [interface.get("IPv4", {}), interface.get("IPv6", {})]:
                    if router := addresses.get("Router"):
                        gateways.add(router)
                    for addr in addresses.get("Addresses", []):
                        ips.add(addr)
                    if dhcp_ip and addresses.get("ConfigMethod", "") == "DHCP":
                        ips.add(dhcp_ip)
                record.ip = list(ips)
                record.dns = list(dns)
                record.gateway = list(gateways)
            except Exception as message:
                self.target.log.warning("Error reading configuration for network device %s: %s.", record.name, message)
                continue

            yield record
