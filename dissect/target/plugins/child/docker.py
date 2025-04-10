from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class DockerChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Docker overlay2fs containers."""

    __type__ = "docker"

    def check_compatible(self) -> None:
        if not self.target.has_function("docker"):
            raise UnsupportedPluginError("No Docker data root folder(s) found!")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for container in self.target.docker.containers():
            if container.mount_path:
                yield ChildTargetRecord(
                    type=self.__type__,
                    path=container.mount_path,
                    _target=self.target,
                )
