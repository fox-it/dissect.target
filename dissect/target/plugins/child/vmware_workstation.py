from flow.record.fieldtypes import uri

from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin


def find_vm_inventory(target):
    for user_details in target.user_details.all_with_home():
        inv_file = user_details.home_path.joinpath("AppData/Roaming/VMware/inventory.vmls")
        if inv_file.exists():
            yield inv_file


class WorkstationChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from VMware Workstation VM inventory."""

    __type__ = "vmware_workstation"

    def __init__(self, target):
        super().__init__(target)
        self.inventories = list(find_vm_inventory(target))

    def check_compatible(self):
        return len(self.inventories) > 0

    def list_children(self):
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
                    path=uri.from_windows(
                        value.strip('"'),
                    ),
                    _target=self.target,
                )
