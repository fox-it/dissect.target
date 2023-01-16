import logging
import re
from typing import Optional

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.network_managers import LinuxNetworkManager
from dissect.target.plugin import OperatingSystem, arg, export, internal
from dissect.target.plugins.os.unix._os import UnixPlugin
from dissect.target.target import Target

log = logging.getLogger(__name__)


class LinuxPlugin(UnixPlugin, LinuxNetworkManager):
    def __init__(self, target: Target):
        super().__init__(target)
        self.network_manager = LinuxNetworkManager(target)
        self.network_manager.discover()

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if fs.exists("/var") and fs.exists("/etc") and fs.exists("/opt") and not fs.exists("/Library"):
                return fs
        return None

    @export(property=False)
    @arg("--dhcp", action="store_true", help="Parse syslogs for recent DHCP leases")
    def ips(self, dhcp: bool = False) -> list[str]:
        """Returns a list of IP addresses found on the host system."""
        ips = []

        for ip_set in self.network_manager.get_config_value("ips"):
            for ip in ip_set:
                ips.append(ip)

        if dhcp:
            for ip in self._parse_dhcp_log_messages():
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
    def version(self) -> str:
        name = self._os_release.get("NAME")
        version = self._os_release.get("VERSION", self._os_release.get("DISTRIB_RELEASE"))
        return f"{name} {version}"

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.LINUX.value

    @internal
    def _parse_dhcp_log_messages(self) -> list[str]:
        """Parse local syslog and cloud init log files for DHCP lease IPs."""

        ips = []

        logs = ["/var/log/syslog", "/var/log/messages"]

        for log in logs:
            if self.target.fs.exists(log):
                for line in self.target.fs.path(log).open("rt"):

                    # ubuntu dhcp
                    if "DHCPv4" in line or "DHCPv6" in line:
                        ip = line.split(" address ")[1].split(" via ")[0].strip().split("/")[0]
                        if ip not in ips:
                            ips.append(ip)

                    # ubuntu dhcp networkmanager
                    if "option ip_address" in line and ("dhcp4" in line or "dhcp6" in line):
                        ip = line.split("=> '")[1].replace("'", "").strip()
                        if ip not in ips:
                            ips.append(ip)

                    # dhclient dhcp for debian and centos
                    if "dhclient" in line and "bound to" in line:
                        ip = line.split("bound to")[1].split(" ")[1].strip()
                        if ip not in ips:
                            ips.append(ip)

                    # networkmanager / centos dhcp
                    if " address " in line and ("dhcp4" in line or "dhcp6" in line):
                        ip = line.split(" address ")[1].strip()
                        if ip not in ips:
                            ips.append(ip)

        # A unix system might be provisioned using Ubuntu's cloud-init.
        # (https://cloud-init.io/)
        #
        # We are interested in the following log entry:
        # YYYY-MM-DD HH:MM:SS,000 - dhcp.py[DEBUG]: Received dhcp lease on IFACE for IP/MASK
        #
        if (path := self.target.fs.path("/var/log/cloud-init.log")).exists():
            for line in path.open("rt"):
                if "Received dhcp lease on" in line:
                    interface, ip, netmask = re.search(
                        r"Received dhcp lease on (\w{0,}) for (\S+)\/(\S+)", line
                    ).groups()
                    if ip not in ips:
                        ips.append(ip)

        return ips
