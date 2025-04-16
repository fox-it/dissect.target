from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from dissect.target.filesystem import LayerFilesystem, VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)


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
        parent_layer = path.joinpath("parent").read_text()

        # iterate over all image layers
        while parent_layer:
            hash_type, layer_hash = parent_layer.split(":")
            layer_ref = root.joinpath("image", "overlay2", "layerdb", hash_type, layer_hash)
            cache_id = layer_ref.joinpath("cache-id").read_text()
            layers.append(("/", root.joinpath("overlay2", cache_id, "diff")))

            parent_layer = parent_file.read_text() if (parent_file := layer_ref.joinpath("parent")).exists() else None

        # add the container layers
        for container_layer_name in ["init-id", "mount-id"]:
            layer = path.joinpath(container_layer_name).read_text()
            layers.append(("/", root.joinpath("overlay2", layer, "diff")))

        # add anonymous volumes, named volumes and bind mounts
        if (config_path := root.joinpath("containers", path.name, "config.v2.json")).exists():
            try:
                config = json.loads(config_path.read_text())
            except json.JSONDecodeError as e:
                log.warning("Unable to parse overlay mounts for container %s", path.name)
                log.debug("", exc_info=e)
                return

            for mount in config.get("MountPoints").values():
                if mount["Type"] not in ["volume", "bind"]:
                    log.warning("Encountered unsupported mount type %s in container %s", mount["Type"], path.name)
                    continue

                if not mount["Source"] and mount["Name"]:
                    # anonymous volumes do not have a Source but a volume id
                    layer = root.joinpath("volumes", mount["Name"], "_data")
                elif mount["Source"]:
                    # named volumes and bind mounts have a Source set
                    layer = root.parents[-1].joinpath(mount["Source"])
                else:
                    log.warning("Could not determine layer source for mount in container %s", path.name)
                    log.debug(json.dumps(mount))
                    continue

                layers.append((mount["Destination"], layer))

        # add hosts, hostname and resolv.conf files
        for file in ["HostnamePath", "HostsPath", "ResolvConfPath"]:
            if not config.get(file) or not (fp := path.parents[-1].joinpath(config.get(file))).exists():
                log.warning("Container %s has no %s mount", path.name, file)
                continue

            layers.append(("/etc/" + fp.name, fp))

        # append and mount every layer
        for dest, layer in layers:
            # we could have collected a layer reference that actually does not exist on the host
            if not layer.exists():
                log.warning(
                    "Can not mount layer %s for container %s as it does not exist on the host", layer, path.name
                )
                continue

            # mount points can be files
            if layer.is_file():
                layer_fs = VirtualFilesystem()
                layer_fs.map_file_fh(dest, layer.open("rb"))

            # regular overlay2 layers are directories
            # mount points can be directories too
            else:
                layer_fs = DirectoryFilesystem(layer)

            log.info("Adding layer %s to destination %s", layer, dest)
            self.append_layer().mount("/" if layer.is_file() else dest, layer_fs)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.base_path}>"
