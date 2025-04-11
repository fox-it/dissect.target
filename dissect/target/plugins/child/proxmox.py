from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class ProxmoxChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from the VM listing."""

    __type__ = "proxmox"

    def check_compatible(self) -> None:
        if self.target.os != "proxmox":
            raise UnsupportedPluginError("Not a Proxmox operating system")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for vm in self.target.vmlist():
            yield ChildTargetRecord(
                type=self.__type__,
                path=vm.path,
                _target=self.target,
            )
