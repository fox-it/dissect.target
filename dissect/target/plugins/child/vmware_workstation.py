from __future__ import annotations

from collections import defaultdict
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

    def inventory_to_dict(self, inventory: TargetPath) -> dict | None:
        config = defaultdict(dict)
        with inventory.open("rt") as fh:
            for line in map(str.strip, fh):
                if not line or line.startswith("."):
                    continue
                try:
                    full_key, value = map(str.strip, line.split("=", 1))
                    vm, key = full_key.split(".", 1)

                    # Only process vmlist entries, not index entries
                    if "vmlist" not in vm:
                        continue

                    config[vm][key] = value.strip('"')
                except ValueError:
                    self.log.warning("Skipping malformed line: %r", line)
                    return None
        return config

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for inv in self.inventories:
            inventory = self.inventory_to_dict(inv)

            for vm in inventory:
                vm_config = inventory[vm]
                yield ChildTargetRecord(
                    name=vm_config.get("DisplayName"),
                    type=self.__type__,
                    path=vm_config.get("config"),
                    _target=self.target,
                )
