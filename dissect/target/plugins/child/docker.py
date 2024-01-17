from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin
from dissect.target.plugins.apps.container.docker import (
    find_installs,  # NOTE: Requires `find_installs` from PR 507
)
from dissect.target.target import Target


class DockerChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Docker overlay2fs containers."""

    __type__ = "docker"

    def __init__(self, target: Target):
        super().__init__(target)
        self.data_roots = set(find_installs(target))

    def check_compatible(self) -> None:
        if not any(self.data_roots):
            raise UnsupportedPluginError("No Docker data root folder(s) found!")

    def list_children(self):
        for data_root in self.data_roots:
            mount_folder = data_root.joinpath("image/overlay2/layerdb/mounts")

            for container in self.target.docker.containers():
                yield ChildTargetRecord(
                    type=self.__type__,
                    path=mount_folder.joinpath(container.container_id),
                    _target=self.target,
                )
