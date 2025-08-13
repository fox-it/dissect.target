from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.hypervisor import vmx

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class ESXiChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from ESXi VM inventory."""

    __type__ = "esxi"

    def check_compatible(self) -> None:
        if self.target.os != "esxi":
            raise UnsupportedPluginError("Not an ESXi operating system")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for vm in self.target.vm_inventory():
            try:
                name = vmx.VMX.parse(self.target.fs.path(vm.path).read_text()).attr.get("displayname")
            except Exception as e:
                self.target.log.exception("Failed parsing displayname from VMX: %s", vm.path)
                self.target.log.debug("", exc_info=e)

                name = None

            yield ChildTargetRecord(
                type=self.__type__,
                name=name,
                path=vm.path,
                _target=self.target,
            )
