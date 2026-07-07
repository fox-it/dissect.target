from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


class VmwareVcenterChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from VMware vCenter support bundle."""

    __type__ = "vmware_vcenter"

    def __init__(self, target: Target):
        super().__init__(target)
        self.hypervisors = list(self.target.fs.glob("/*@*.tgz"))

    def check_compatible(self) -> None:
        if not self.hypervisors:
            raise UnsupportedPluginError("No Vmware Vcenter childs found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for hypervisor in self.hypervisors:
            yield ChildTargetRecord(
                type=self.__type__,
                path=hypervisor,
                _target=self.target,
            )
