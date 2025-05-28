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

    def _get_child_name(self, vm_path: str) -> str | None:
        try:
            with self.target.fs.path(vm_path).open("rt") as fh:
                strings = fh.read()
                return vmx._parse_dictionary(strings).get("displayname")
        except Exception as e:
            self.target.log.error("Failed parsing displayname from vm_path=%s", vm_path)
            self.target.log.debug("", exc_info=e)
        return None

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for vm in self.target.vm_inventory():
            yield ChildTargetRecord(
                name=self._get_child_name(vm.path),
                type=self.__type__,
                path=vm.path,
                _target=self.target,
            )
