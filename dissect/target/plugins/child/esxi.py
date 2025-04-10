from __future__ import annotations

from typing import TYPE_CHECKING

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
            yield ChildTargetRecord(
                type=self.__type__,
                path=vm.path,
                _target=self.target,
            )
