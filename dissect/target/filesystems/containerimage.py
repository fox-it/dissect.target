from __future__ import annotations

import json
import logging
from pathlib import Path

from dissect.target.filesystem import LayerFilesystem
from dissect.target.filesystems.tar import TarFilesystem

log = logging.getLogger(__name__)


class ContainerImageFilesystem(LayerFilesystem):
    """Container image filesystem implementation.

    ..code-block::

        docker image save example:latest -o image.tar

    References:
        - https://snyk.io/blog/container-image-formats/
        - https://github.com/moby/docker-image-spec/
        - https://github.com/opencontainers/image-spec/
    """

    __type__ = "container_image"

    def __init__(self, path: Path, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._path = path
        self.tar = TarFilesystem(path.open("rb"))

        try:
            self.manifest = json.loads(self.tar.path("/manifest.json").read_text())[0]
        except Exception as e:
            self.manifest = None
            raise ValueError(f"Unable to read manifest.json inside docker image filesystem: {str(e)}")

        self.name = self.manifest.get("RepoTags", [None])[0]

        try:
            self.config = json.loads(self.tar.path(self.manifest.get("Config")).read_text())
        except Exception as e:
            self.config = None
            raise ValueError(f"Unable to read config inside docker image filesystem: {str(e)}")

        for layer in [self.tar.path(p) for p in self.manifest.get("Layers", [])]:
            if not layer.exists():
                log.warning("Layer %s does not exist in container image", layer)
                continue

            fs = TarFilesystem(layer.open("rb"))
            self.append_fs_layer(fs)

        self.append_layer().mount("$fs$/container", self.tar)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} path={self._path} name={self.name}>"
