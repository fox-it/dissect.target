import logging
from typing import Optional

from dissect.target.filesystem import Filesystem
from dissect.target.plugins.os.unix._os import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.target import Target

log = logging.getLogger(__name__)

PROXMOX_PACKAGE_NAME="proxmox-ve"


class ProxmoxPlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if (fs.exists("/etc/pve") or fs.exists("/var/lib/pve")):
                return fs
        return None

    @export(property=True)
    def version(self) -> str:
            """Returns Proxmox VE version with underlying os release"""

            for pkg in self.target.dpkg.status():
                if pkg.name == PROXMOX_PACKAGE_NAME:
                    distro_name = self._os_release.get("PRETTY_NAME", "")
                    return f"{pkg.name} {pkg.version} ({distro_name})"

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.PROXMOX.value

