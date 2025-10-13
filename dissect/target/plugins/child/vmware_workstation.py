from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin
from dissect.target.plugins.apps.virtualization.vmware_workstation import find_vm_inventory, parse_inventory_file

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


class VmwareWorkstationChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from VMware Workstation VM inventory."""

    __type__ = "vmware_workstation"

    def __init__(self, target: Target):
        super().__init__(target)
        self.inventories = [inventory for inventory, _ in find_vm_inventory(target)]

    def check_compatible(self) -> None:
        if not self.inventories:
            raise UnsupportedPluginError("No VMWare inventories found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for inv in self.inventories:
            inventory = parse_inventory_file(inv)

            for config in inventory.values():
                yield ChildTargetRecord(
                    type=self.__type__,
                    name=config.get("DisplayName"),
                    path=config.get("config"),
                    _target=self.target,
                )
