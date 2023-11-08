from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin


class DockerChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields from Docker overlay2fs containers."""

    __type__ = "docker"

    def check_compatible(self) -> None:
        if not self.target.fs.path("/var/lib/docker").exists():
            raise UnsupportedPluginError("No Docker folder found!")

    def list_children(self):
        mount_folder = self.target.fs.path("/var/lib/docker/image/overlay2/layerdb/mounts/")

        for container in self.target.docker.containers():
            yield ChildTargetRecord(
                type=self.__type__,
                path=mount_folder.joinpath(container.container_id),
                _target=self.target,
            )
