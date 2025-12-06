from __future__ import annotations

from typing import TYPE_CHECKING

from defusedxml import ElementTree

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


VirtualMachineRecord = TargetRecordDescriptor(
    "esxi/vm",
    [
        ("path", "path"),
    ],
)


class VirtualMachinePlugin(Plugin):
    """Plugin to list ESXi virtual machines."""

    def check_compatible(self) -> None:
        if self.target.os != "esxi":
            raise UnsupportedPluginError("ESXi specific plugin loaded on non-ESXi target")

        if not self.target.fs.path("/etc/vmware/hostd/vmInventory.xml").exists():
            raise UnsupportedPluginError("vmInventory.xml not found on target")

    @export(record=VirtualMachineRecord)
    def vm_inventory(self) -> Iterator[VirtualMachineRecord]:
        """Yield all virtual machines registered on the ESXi host."""
        if (inv_file := self.target.fs.path("/etc/vmware/hostd/vmInventory.xml")).is_file():
            root = ElementTree.fromstring(inv_file.read_text())
            for entry in root.iter("ConfigEntry"):
                yield VirtualMachineRecord(
                    path=self.target.fs.path(entry.findtext("vmxCfgPath")),
                    _target=self.target,
                )
