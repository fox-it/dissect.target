from pathlib import Path

from dissect.target.filesystem import LayerFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem


class Overlay2Filesystem(LayerFilesystem):
    """Overlay 2 filesystem implementation.

    Deleted files will be present on the reconstructed filesystem.

    References:
        - https://www.didactic-security.com/resources/docker-forensics.pdf
        - https://www.didactic-security.com/resources/docker-forensics-cheatsheet.pdf
        - https://github.com/google/docker-explorer
    """

    __type__ = "overlay2"

    def __init__(self, path: Path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.base_path = path

        # base_path is /foo/bar/image/overlay2/layerdb/mounts/<id> so we traverse up to /foo/bar to get to the root.
        root = path.parents[4]

        layers = []
        parent_layer = path.joinpath("parent").open("r").read()

        # iterate over all image layers
        while parent_layer:
            hash_type, layer_hash = parent_layer.split(":")
            layer_ref = root.joinpath(f"image/overlay2/layerdb/{hash_type}/{layer_hash}")
            cache_id = layer_ref.joinpath("cache-id").open("r").read()
            layers.append(root.joinpath(f"overlay2/{cache_id}/diff"))

            if not (parent_layer := layer_ref.joinpath("parent")).exists():
                parent_layer = False

        # add the container layers
        for container_layer_name in ["init-id", "mount-id"]:
            layer = path.joinpath(container_layer_name).open("r").read()
            layers.append(root.joinpath(f"overlay2/{layer}/diff"))

        # add every diff directory
        for layer in layers:
            layer_fs = DirectoryFilesystem(layer)
            self.add_fs_layer(layer_fs)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.base_path}>"
