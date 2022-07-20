from dissect.hypervisor import hyperv
from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin


class HyperVChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Hyper-V VM inventory.

    Hyper-V VMs are registered in a data.vmcx file in the Hyper-V ProgramData directory.
    """

    __type__ = "hyper-v"

    PATH = "sysvol/ProgramData/Microsoft/Windows/Hyper-V/data.vmcx"

    def check_compatible(self):
        if not self.target.fs.path(self.PATH).exists():
            raise UnsupportedPluginError("No data.vmcx file found")

    def list_children(self):
        fh = self.target.fs.path(self.PATH).open()
        data = hyperv.HyperVFile(fh).as_dict()

        for path in data["Configurations"]["VirtualMachines"].values():
            yield ChildTargetRecord(
                type=self.__type__,
                path=uri.from_windows(path),
                _target=self.target,
            )
