import logging
from typing import List, Optional

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
    def ips(self) -> List[str]:
        return self.network_manager.get_config_value("ips")

    @export(property=True)
    def dns(self) -> List[str]:
        return self.network_manager.get_config_value("dns")

    @export(property=True)
    def dhcp(self) -> List[bool]:
        return self.network_manager.get_config_value("dhcp")

    @export(property=True)
    def gateway(self) -> List[str]:
        return self.network_manager.get_config_value("gateway")

    @export(property=True)
    def interface(self) -> List[str]:
        return self.network_manager.get_config_value("interface")

    @export(property=True)
    def netmask(self) -> List[str]:
        return self.network_manager.get_config_value("netmask")

    @export(property=True)
    def version(self) -> str:
        name = self.os_release.get("NAME")
        version = self.os_release.get("VERSION", self.os_release.get("DISTRIB_RELEASE"))
        return f"{name} {version}"

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.LINUX.value

    @export(property=True)
    def architecture(self) -> Optional[str]:
        return super().architecture(self.os)
