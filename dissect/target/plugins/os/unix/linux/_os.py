import logging
from typing import Optional

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.network_managers import LinuxNetworkManager
from dissect.target.plugin import OperatingSystem, export
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

    @export(property=True)
    def ips(self) -> list[str]:
        return self.network_manager.get_config_value("ips")

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
