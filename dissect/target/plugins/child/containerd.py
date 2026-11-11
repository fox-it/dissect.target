from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class ContainerdChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Containerd overlayfs containers."""

    __type__ = "containerd"

    def check_compatible(self) -> None:
        if not self.target.has_function("containerd"):
            raise UnsupportedPluginError("No Containerd install(s) found on target")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for container in self.target.containerd.containers():
            if container.mount_path:
                yield ChildTargetRecord(
                    type=self.__type__,
                    name=container.name,
                    path=container.mount_path,
                    _target=self.target,
                )
