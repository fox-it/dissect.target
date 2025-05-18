from __future__ import annotations

import plistlib
from functools import cache, lru_cache
from typing import TYPE_CHECKING

from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers.record import MacOSInterfaceRecord
from dissect.target.plugins.os.default.network import NetworkPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


class MacOSNetworkPlugin(NetworkPlugin):
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
            return plistlib.load(preferences.open()) or {}

        raise FileNotFoundError("Couldn't find preferences file")

    def _interfaces(self) -> Iterator[MacOSInterfaceRecord]:
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
            device = interface.get("Interface", {})
            name = device.get("DeviceName")
            _type = device.get("Type")
            vlan = vlan_lookup.get(name)
            dhcp = False
            ifaces = set()
            interface_service_order = service_order.index(_id) if _id in service_order else None
            try:
                for addr in interface.get("DNS", {}).get("ServerAddresses", {}):
                    dns.add(addr)

                for addresses in [interface.get("IPv4", {}), interface.get("IPv6", {})]:
                    iface = ""
                    if router := addresses.get("Router"):
                        gateways.add(router)

                    if addresses.get("ConfigMethod", "") == "DHCP":
                        iface = self._plistlease(name).get("IPAddress")
                        dhcp = True
                    elif addr := addresses.get("Addresses", []):
                        iface = addr[0]

                    if _subnet_mask := list(filter(None, addresses.get("SubnetMasks", []))):
                        iface = f"{iface}/{_subnet_mask[0]}"

                    if iface:
                        ifaces.add(iface)

                yield MacOSInterfaceRecord(
                    name=name,
                    type=_type,
                    enabled=not interface.get("__INACTIVE__", False),
                    cidr=ifaces,
                    gateway=list(gateways),
                    dns=list(dns),
                    mac=[],
                    source="NetworkServices",
                    interface_service_order=interface_service_order,
                    dhcp=dhcp,
                    vlan=vlan,
                    _target=self.target,
                )

            except Exception as e:
                self.target.log.warning("Error reading configuration for network device %s", name)
                self.target.log.debug("", exc_info=e)
