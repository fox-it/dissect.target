from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

INVENTORY_PATHS = [
    # Windows
    "AppData/Roaming/VMware/inventory.vmls",
    # Linux
    ".vmware/inventory.vmls",
]


def find_vm_inventory(target: Target) -> Iterator[TargetPath]:
    """Search for inventory.vmls files in user home folders.

    Does not support older vmAutoStart.xml or vmInventory.xml formats."""

    for user_details in target.user_details.all_with_home():
        for inv_path in INVENTORY_PATHS:
            if (inv_file := user_details.home_path.joinpath(inv_path)).exists():
                yield inv_file


class VmwareWorkstationChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from VMware Workstation VM inventory."""

    __type__ = "vmware_workstation"

    def __init__(self, target: Target):
        super().__init__(target)
        self.inventories = list(find_vm_inventory(target))

    def check_compatible(self) -> None:
        if not self.inventories:
            raise UnsupportedPluginError("No VMWare inventories found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for inv in self.inventories:
            for line in inv.open("rt"):
                line = line.strip()
                if not line.startswith("vmlist"):
                    continue

                key, _, value = line.partition("=")
                if not key.strip().endswith(".config"):
                    continue

                value = value.strip().strip('"')
                if value.startswith("folder") or not value:
                    continue

                yield ChildTargetRecord(
                    type=self.__type__,
                    path=self.target.fs.path(value.strip('"')),
                    _target=self.target,
                )
