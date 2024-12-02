from __future__ import annotations

import plistlib
from functools import cache, lru_cache
from typing import Iterator

from dissect.target.helpers.record import MacInterfaceRecord
from dissect.target.plugins.general.network import NetworkPlugin
from dissect.target.target import Target


class MacNetworkPlugin(NetworkPlugin):
    """macOS network interface plugin."""

    def __init__(self, target: Target):
        super().__init__(target)
        self._plistnetwork = cache(self._plistnetwork)
        self._plistlease = lru_cache(32)(self._plistlease)

    def _plistlease(self, devname: str) -> dict:
        for lease in self.target.fs.glob_ext(f"/private/var/db/dhcpclient/leases/{devname}*"):
            return plistlib.load(lease.open())
        return {}

    def _plistnetwork(self) -> dict:
        if (preferences := self.target.fs.path("/Library/Preferences/SystemConfiguration/preferences.plist")).exists():
            return plistlib.load(preferences.open())

    def _interfaces(self) -> Iterator[MacInterfaceRecord]:
        plistnetwork = self._plistnetwork()
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

        vlan_lookup = {key: vlan.get("Tag") for key, vlan in vlans.items()}

        for _id, interface in network.items():
            dns = set()
            gateways = set()
            ips = set()
            device = interface.get("Interface", {})
            name = device.get("DeviceName")
            _type = device.get("Type")
            vlan = vlan_lookup.get(name)
            dhcp = False
            subnetmask = []
            network = []
            interface_service_order = service_order.index(_id) if _id in service_order else None
            try:
                for addr in interface.get("DNS", {}).get("ServerAddresses", {}):
                    dns.add(addr)
                for addresses in [interface.get("IPv4", {}), interface.get("IPv6", {})]:
                    subnetmask += filter(lambda mask: mask != "", addresses.get("SubnetMasks", []))
                    if router := addresses.get("Router"):
                        gateways.add(router)
                    if addresses.get("ConfigMethod", "") == "DHCP":
                        ips.add(self._plistlease(name).get("IPAddress"))
                        dhcp = True
                    else:
                        for addr in addresses.get("Addresses", []):
                            ips.add(addr)

                if subnetmask:
                    network = self.calculate_network(ips, subnetmask)

                yield MacInterfaceRecord(
                    name=name,
                    type=_type,
                    enabled=not interface.get("__INACTIVE__", False),
                    dns=list(dns),
                    ip=list(ips),
                    gateway=list(gateways),
                    source="NetworkServices",
                    vlan=vlan,
                    network=network,
                    interface_service_order=interface_service_order,
                    dhcp=dhcp,
                    mac=[],
                    _target=self.target,
                )

            except Exception as e:
                self.target.log.warning("Error reading configuration for network device %s", name, exc_info=e)
                continue
