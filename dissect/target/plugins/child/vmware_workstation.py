from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin
from dissect.target.plugins.apps.virtualization.vmware_workstation import find_vm_inventory

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


def parse_vm_inventory(path: Path) -> dict[str, dict[str, str]]:
    config = {}

    with path.open("rt") as fh:
        for line in fh:
            if not (line := line.strip()) or line.startswith("."):
                continue

            full_key, value = line.split("=", 1)
            vm, key = full_key.strip().split(".", 1)

            # Only process vmlist entries, not index entries
            if "vmlist" not in vm:
                continue

            config.setdefault(vm, {})[key] = value.strip().strip('"')

    return config


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
            inventory = parse_vm_inventory(inv)

            for config in inventory.values():
                yield ChildTargetRecord(
                    type=self.__type__,
                    name=config.get("DisplayName"),
                    path=config.get("config"),
                    _target=self.target,
                )
