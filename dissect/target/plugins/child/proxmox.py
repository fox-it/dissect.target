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

    def _get_child_name(self, vm_path: str) -> str | None:
        try:
            vm_path = self.target.fs.path(vm_path)
            with vm_path.open("rt") as fh:
                for line in map(str.strip, fh):
                    if not line:
                        continue

                    if (key_value := line.split(":", 1)) and key_value[0] == "name":
                        return key_value[1].strip()
        except Exception as e:
            self.target.log.error("Failed parsing name from vm_path=%s", vm_path)
            self.target.log.debug("", exc_info=e)
        return None

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for vm in self.target.vmlist():
            yield ChildTargetRecord(
                name=self._get_child_name(vm.path),
                type=self.__type__,
                path=vm.path,
                _target=self.target,
            )
