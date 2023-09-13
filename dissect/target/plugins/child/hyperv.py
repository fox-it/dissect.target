from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

from dissect.hypervisor import hyperv
from flow.record.fieldtypes import path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


class HyperVChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Hyper-V VM inventory.

    Since Windows Server 2016, Hyper-V VMs are registered in a data.vmcx file in the Hyper-V ProgramData directory.
    Before that, VMs were registered by having a .xml file in the Hyper-V ProgramData "Virtual Machines" directory.

    It is possible to put your "VM descriptor" files elsewhere. In the .vmcx format, the full path to the alternative
    location is stored. In the .xml format, a NTFS symlink reparse point is created that points to the full
    alternative path.
    """

    __type__ = "hyper-v"

    PATH = "sysvol/ProgramData/Microsoft/Windows/Hyper-V"

    def __init__(self, target: Target):
        super().__init__(target)

        hyperv_path = self.target.fs.path(self.PATH)
        self.data_vmcx = hyperv_path.joinpath("data.vmcx")
        self.vm_xml = list(hyperv_path.joinpath("Virtual Machines").glob("*.xml"))

    def check_compatible(self) -> None:
        if not self.data_vmcx.exists() and not self.vm_xml:
            raise UnsupportedPluginError("No registered VMs and no data.vmcx file found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        if self.data_vmcx.exists():
            data = hyperv.HyperVFile(self.data_vmcx.open()).as_dict()

            if virtual_machines := data["Configurations"].get("VirtualMachines"):
                for vm_path in virtual_machines.values():
                    yield ChildTargetRecord(
                        type=self.__type__,
                        path=path.from_windows(vm_path),
                        _target=self.target,
                    )

        for xml_path in self.vm_xml:
            yield ChildTargetRecord(
                type=self.__type__,
                path=xml_path.resolve(),
                _target=self.target,
            )
