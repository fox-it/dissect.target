from __future__ import annotations

from typing import TYPE_CHECKING

from defusedxml import ElementTree

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


VirtualMachineInventoryRecord = TargetRecordDescriptor(
    "esxi/vm/inventory",
    [
        ("path", "path"),
    ],
)

VirtualMachineOrphanRecord = TargetRecordDescriptor(
    "esxi/vm/orphaned",
    [
        ("path", "path"),
    ],
)


class VirtualMachinePlugin(Plugin):
    """Plugin to list ESXi virtual machines."""

    __namespace__ = "vm"

    def check_compatible(self) -> None:
        if self.target.os != "esxi":
            raise UnsupportedPluginError("ESXi specific plugin loaded on non-ESXi target")

        if not self.target.fs.path("/etc/vmware/hostd/vmInventory.xml").exists():
            raise UnsupportedPluginError("vmInventory.xml not found on target")

    @export(record=VirtualMachineInventoryRecord)
    def inventory(self) -> Iterator[VirtualMachineInventoryRecord]:
        """Yield all virtual machines registered on the ESXi host."""
        if (inv_file := self.target.fs.path("/etc/vmware/hostd/vmInventory.xml")).is_file():
            root = ElementTree.fromstring(inv_file.read_text())
            for entry in root.iter("ConfigEntry"):
                yield VirtualMachineInventoryRecord(
                    path=self.target.fs.path(entry.findtext("vmxCfgPath")),
                    _target=self.target,
                )

    @export(record=VirtualMachineOrphanRecord)
    def orphaned(self) -> Iterator[VirtualMachineOrphanRecord]:
        """Yield all virtual machines found at ``/vmfs/volumes/*/*/*.vmx`` that are NOT in the inventory.

        NOTE: If the target is part of a cluster, this may yield "false positives" for VMs registered
        on other hosts in the cluster.
        """
        inventory = {str(r.path) for r in self.inventory()}

        for vmx_path in self.target.fs.path("/vmfs/volumes").glob("*/*/*.vmx"):
            if str(vmx_path) not in inventory:
                yield VirtualMachineOrphanRecord(
                    path=vmx_path,
                    _target=self.target,
                )
