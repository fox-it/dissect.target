from dissect.target.filesystems.overlay import Overlay2Filesystem, Overlay2LayerFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.loader import Loader
from dissect.target.target import Target


class Overlay2Loader(Loader):
    """Load Docker overlay2 filesystems.

    NOTE:
        - Deleted files will still be present on the reconstructed filesystem.
        - Older files are 'overwritten' by newer versions.

    References:
        - https://www.didactic-security.com/resources/docker-forensics.pdf
        - https://www.didactic-security.com/resources/docker-forensics-cheatsheet.pdf
        - https://github.com/google/docker-explorer
    """

    def __init__(self, path: TargetPath, **kwargs):
        super().__init__(path.resolve(), **kwargs)

    @staticmethod
    def detect(path: TargetPath) -> bool:

        # path should be a folder
        if not path.is_dir():
            return False

        # with the following three files
        for required_file in ["init-id", "parent", "mount-id"]:
            if not path.joinpath(required_file).exists():
                return False

        # and should have at least 5 parent folders
        if not len(path.parts) >= 5:
            return False

        return True

    def map(self, target: Target) -> None:
        """Collect all layers and present them as one filesystem."""

        # strip image/overlay2/layerdb/mounts/<id> from path so the docker root remains
        docker_root = self.path.parent.parent.parent.parent.parent

        layers = []
        parent = self.path.joinpath("parent").open("r").read()

        # iterate over all image layers
        while parent:
            hash_type, layer_hash = parent.split(":")
            layer_ref = docker_root.joinpath(f"image/overlay2/layerdb/{hash_type}/{layer_hash}")
            cache_id = layer_ref.joinpath("cache-id").open("r").read()

            layers.append(docker_root.joinpath(f"overlay2/{cache_id}/diff"))

            # have we reached the last layer of the image?
            if not (parent := layer_ref.joinpath("parent")).exists():
                parent = False

        # add the container layers
        for container_layer_name in ["init-id", "mount-id"]:
            layer = self.path.joinpath(container_layer_name).open("r").read()
            layers.append(docker_root.joinpath(f"overlay2/{layer}/diff"))

        # mount every diff directory to root
        overlay_fs = Overlay2Filesystem()

        for layer in layers:
            layer_fs = Overlay2LayerFilesystem(layer)
            overlay_fs.mount(layer_fs)

        # add the overlay filesystem to the target
        target.filesystems.add(overlay_fs)
