from __future__ import annotations

import logging

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.network_managers import (
    LinuxNetworkManager,
    parse_unix_dhcp_log_messages,
)
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.plugins.os.unix.bsd.osx._os import MacPlugin
from dissect.target.plugins.os.windows._os import WindowsPlugin
from dissect.target.target import Target

log = logging.getLogger(__name__)


class LinuxPlugin(UnixPlugin, LinuxNetworkManager):
    def __init__(self, target: Target):
        super().__init__(target)
        self.network_manager = LinuxNetworkManager(target)
        self.network_manager.discover()

    @classmethod
    def detect(cls, target: Target) -> Filesystem | None:
        for fs in target.filesystems:
            if (
                (fs.exists("/var") and fs.exists("/etc") and fs.exists("/opt"))
                or (fs.exists("/sys/module") or fs.exists("/proc/sys"))
            ) and not (MacPlugin.detect(target) or WindowsPlugin.detect(target)):
                return fs

    @export(property=True)
    def ips(self) -> list[str]:
        """Returns a list of static IP addresses and DHCP lease IP addresses found on the host system."""
        ips = []

        for ip_set in self.network_manager.get_config_value("ips"):
            for ip in ip_set:
                ips.append(ip)

        for ip in parse_unix_dhcp_log_messages(self.target, iter_all=False):
            if ip not in ips:
                ips.append(ip)

        return ips

    @export(property=True)
    def dns(self) -> list[str]:
        return self.network_manager.get_config_value("dns")

    @export(property=True)
    def dhcp(self) -> list[bool]:
        return self.network_manager.get_config_value("dhcp")

    @export(property=True)
    def gateway(self) -> list[str]:
        return self.network_manager.get_config_value("gateway")

    @export(property=True)
    def interface(self) -> list[str]:
        return self.network_manager.get_config_value("interface")

    @export(property=True)
    def netmask(self) -> list[str]:
        return self.network_manager.get_config_value("netmask")

    @export(property=True)
    def version(self) -> str | None:
        distrib_description = self._os_release.get("DISTRIB_DESCRIPTION", "")
        name = self._os_release.get("NAME", "") or self._os_release.get("DISTRIB_ID", "")
        version = (
            self._os_release.get("VERSION", "")
            or self._os_release.get("VERSION_ID", "")
            or self._os_release.get("DISTRIB_RELEASE", "")
        )

        if len(f"{name} {version}") > len(distrib_description):
            distrib_description = f"{name} {version}"

        return distrib_description or None

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.LINUX.value
