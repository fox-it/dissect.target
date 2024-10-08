from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

VirtualMachineRecord = TargetRecordDescriptor(
    "proxmox/vm",
    [
        ("string", "path"),
    ],
)


class VirtualMachinePlugin(Plugin):
    """Plugin to list Proxmox virtual machines."""

    def check_compatible(self) -> None:
        if self.target.os != "proxmox":
            raise UnsupportedPluginError("Not a Proxmox operating system")

    @export(record=VirtualMachineRecord)
    def vmlist(self) -> Iterator[VirtualMachineRecord]:
        """List Proxmox virtual machines on this node."""
        for config in self.target.fs.path("/etc/pve/qemu-server").iterdir():
            yield VirtualMachineRecord(
                path=config,
                _target=self.target,
            )
