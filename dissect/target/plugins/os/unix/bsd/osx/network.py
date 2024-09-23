from __future__ import annotations

import plistlib
from functools import cache
from typing import Iterator

from dissect.target.helpers.record import MacInterfaceRecord
from dissect.target.plugins.general.network import NetworkPlugin


class MacNetworkPlugin(NetworkPlugin):
    @cache
    def _plistlease(self) -> dict:
        if (dhcp := self.target.fs.path("/private/var/db/dhcpclient/leases")).exists():
            for lease in dhcp.iterdir():
                if lease.is_file():
                    return plistlib.load(lease.open())
        return {}

    @cache
    def _plistnetwork(self) -> dict:
        if (preferences := self.target.fs.path("/Library/Preferences/SystemConfiguration/preferences.plist")).exists():
            return plistlib.load(preferences.open())

    def _interfaces(self) -> Iterator[MacInterfaceRecord]:
        plistlease = self._plistlease()
        plistnetwork = self._plistnetwork()

        dhcp_ip = plistlease.get("IPAddress")

        current_set = plistnetwork.get("CurrentSet")
        sets = plistnetwork.get("Sets", {})
        for name, _set in sets.items():
            if f"/Sets/{name}" == current_set:
                item = _set
                for key in ["Network", "Global", "IPv4", "ServiceOrder"]:
                    item = item.get(key, {})
                service_order = item
                break

        network = plistnetwork.get("NetworkServices", {})
        vlans = plistnetwork.get("VirtualNetworkInterfaces", {}).get("VLAN", {})
        vlan_lookup = {}
        for key, vlan in vlans.items():
            vlan_lookup[key] = vlan.get("Tag")

        for _id, interface in network.items():
            dns = set()
            gateways = set()
            ips = set()
            data = {}
            data["source"] = "NetworkServices"
            device = interface.get("Interface", {})
            data["name"] = device.get("DeviceName")
            data["type"] = device.get("Type")
            data["vlan"] = vlan_lookup.get(data["name"])
            data["dhcp"] = False
            subnetmask = []
            data["interface_service_order"] = service_order.index(_id) if _id in service_order else None
            try:
                data["enabled"] = not interface.get("__INACTIVE__", False)
                for addr in interface.get("DNS", {}).get("ServerAddresses", {}):
                    dns.add(addr)
                for addresses in [interface.get("IPv4", {}), interface.get("IPv6", {})]:
                    subnetmask += filter(lambda mask: mask != "", addresses.get("SubnetMasks", []))
                    if router := addresses.get("Router"):
                        gateways.add(router)
                    if dhcp_ip and addresses.get("ConfigMethod", "") == "DHCP":
                        ips.add(dhcp_ip)
                        data["dhcp"] = True
                    else:
                        for addr in addresses.get("Addresses", []):
                            ips.add(addr)

                data["ip"] = list(ips)
                data["dns"] = list(dns)
                data["gateway"] = list(gateways)

                if subnetmask:
                    data["network"] = self.calculate_network(ips, data["subnetmask"])

                yield MacInterfaceRecord(_target=self.target, **data)

            except Exception as e:
                self.target.log.warning("Error reading configuration for network device %s: %s", data["name"], e)
                continue
