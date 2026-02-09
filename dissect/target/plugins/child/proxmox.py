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
            vm_path = self.target.fs.path(vm.path)

            name = None
            try:
                with vm_path.open("rt") as fh:
                    for line in fh:
                        if not (line := line.strip()):
                            continue

                        if (key_value := line.split(":", 1)) and key_value[0] == "name":
                            name = key_value[1].strip()
                            break
            except Exception as e:
                self.target.log.error("Failed parsing name from VM config: %s", vm_path)  # noqa: TRY400
                self.target.log.debug("", exc_info=e)

            yield ChildTargetRecord(
                type=self.__type__,
                name=name,
                path=vm_path,
                _target=self.target,
            )
