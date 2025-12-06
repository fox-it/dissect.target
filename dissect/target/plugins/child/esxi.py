from __future__ import annotations

from itertools import chain
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
        seen = set()

        for path in chain(
            (vm.path for vm in self.target.vm_inventory()), self.target.fs.path("/vmfs/volumes").glob("*/*/*.vmx")
        ):
            if str(path) in seen:
                continue
            seen.add(str(path))

            try:
                name = vmx.VMX.parse(self.target.fs.path(path).read_text()).attr.get("displayname")
            except Exception as e:
                self.target.log.error("Failed parsing displayname from VMX: %s", path)  # noqa: TRY400
                self.target.log.debug("", exc_info=e)

                name = None

            yield ChildTargetRecord(
                type=self.__type__,
                name=name,
                path=path,
                _target=self.target,
            )
