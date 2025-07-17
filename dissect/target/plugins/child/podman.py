from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class PodmanChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Podman overlayfs containers."""

    __type__ = "podman"

    def check_compatible(self) -> None:
        if not self.target.has_function("podman"):
            raise UnsupportedPluginError("No Podman install(s) found on target")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for container in self.target.podman.containers():
            if container.mount_path:
                yield ChildTargetRecord(
                    type=self.__type__,
                    path=container.mount_path,
                    _target=self.target,
                )
