from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin


class ESXiChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from ESXi VM inventory."""

    __type__ = "esxi"

    def check_compatible(self):
        return self.target.os == "esxi"

    def list_children(self):
        for vm in self.target.vm_inventory():
            yield ChildTargetRecord(
                type=self.__type__,
                path=vm.path,
                _target=self.target,
            )
