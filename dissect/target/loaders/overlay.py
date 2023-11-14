from dissect.target.filesystems.overlay import OverlayFilesystem, OverlayLayerFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.loader import Loader
from dissect.target.target import Target


class OverlayLoader(Loader):
    """Load Docker overlay2 filesystems.

    NOTE: Symlinks are not working correctly yet.

    References:
        - https://www.didactic-security.com/resources/docker-forensics.pdf
        - https://www.didactic-security.com/resources/docker-forensics-cheatsheet.pdf
        - https://github.com/google/docker-explorer
    """

    def __init__(self, path: TargetPath, **kwargs):
        path = path.resolve()
        super().__init__(path)

    @staticmethod
    def detect(path: TargetPath) -> bool:
        return str(path).lower().startswith("/var/lib/docker")
        # TODO: check if the provided folder (iterdir) contains
        # files that we need!

    def map(self, target: Target) -> None:
        """Attempt to collect all layers and present them as one filesystem."""
        docker_root = self.path.get().fs.path("/var/lib/docker")
        layers = []

        parent = self.path.joinpath("parent").open("r").read()

        # iterate over all image layers
        while parent:
            hash_type, layer_hash = parent.split(":")
            layer_ref = docker_root.joinpath(f"image/overlay2/layerdb/{hash_type}/{layer_hash}")
            cache_id = layer_ref.joinpath("cache-id").open("r").read()

            layers.append(docker_root.joinpath(f"overlay2/{cache_id}/diff"))

            if not (parent := layer_ref.joinpath("parent")).exists():
                parent = False

        # add the container layers
        for container_layer_name in ["init-id", "mount-id"]:
            layer = self.path.joinpath(container_layer_name).open("r").read()
            layers.append(docker_root.joinpath(f"overlay2/{layer}/diff"))

        # mount every diff directory to root
        overlay_fs = OverlayFilesystem()

        for layer in layers:
            layer_fs = OverlayLayerFilesystem(layer)
            overlay_fs.mount(layer_fs)

        # add the overlay filesystem to the target
        target.filesystems.add(overlay_fs)
