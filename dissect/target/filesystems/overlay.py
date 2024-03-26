import json
from pathlib import Path

from dissect.target.filesystem import LayerFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem


class Overlay2Filesystem(LayerFilesystem):
    """Overlay 2 filesystem implementation.

    Deleted files will be present on the reconstructed filesystem.
    Volumes and bind mounts will be added to their respective mount locations.
    Does not support tmpfs mounts.

    References:
        - https://docs.docker.com/storage/storagedriver/
        - https://docs.docker.com/storage/volumes/
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

            if (parent_layer := layer_ref.joinpath("parent")).exists():
                parent_layer = parent_layer.open("r").read()
            else:
                parent_layer = False

        # add the container layers
        for container_layer_name in ["init-id", "mount-id"]:
            layer = path.joinpath(container_layer_name).open("r").read()
            layers.append(root.joinpath(f"overlay2/{layer}/diff"))

        # add every diff directory
        for layer in layers:
            layer_fs = DirectoryFilesystem(layer)
            self.add_fs_layer(layer_fs)

        # add anonymous volumes, named volumes and bind mounts
        if (config_path := root / "containers" / path.name / "config.v2.json").exists():
            try:
                config = json.loads(config_path.read_text())
            except json.JSONDecodeError as e:
                path._fs.target.log.warning("Unable to parse overlay mounts for container %s", path.name)
                path._fs.target.log.debug("", exc_info=e)
                return

            for mount in config.get("MountPoints").values():
                if not mount["Type"] in ["volume", "bind"]:
                    path._fs.target.log.warning(
                        "Encountered unsupported mount type %s in container %s", mount["Type"], path.name
                    )
                    continue

                if not mount["Source"] and mount["Name"]:
                    # anonymous volumes do not have a Source but a volume id
                    layer_fs = DirectoryFilesystem(root / "volumes" / mount["Name"] / "_data")
                elif mount["Source"]:
                    # named volumes and bind mounts have a Source set
                    layer_fs = DirectoryFilesystem(root.parents[-1] / mount["Source"])
                else:
                    path._fs.target.log.warning("Could not determine layer source for mount in container %s", path.name)
                    path._fs.target.log.debug(json.dumps(mount))

                self.mount(mount["Destination"], layer_fs)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.base_path}>"
