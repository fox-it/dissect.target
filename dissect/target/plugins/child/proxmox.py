from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin


class ProxmoxChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from the VM listing."""

    __type__ = "proxmox"

    def check_compatible(self) -> None:
        if self.target.os != "proxmox":
            raise UnsupportedPluginError("Not an promox operating system")

    def list_children(self):
        for vm in self.target.vm_list():
            yield ChildTargetRecord(
                type=self.__type__,
                path=vm.config_path,
                _target=self.target,
            )
