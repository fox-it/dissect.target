from __future__ import annotations

import json
import logging

from dissect.target.filesystem import LayerFilesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.loader import Loader
from dissect.target.loaders.tar import TarLoader
from dissect.target.target import Target

log = logging.getLogger(__name__)

DOCKER_ARCHIVE_IMAGE = {
    "/manifest.json",
    "/repositories",
}

OCI_IMAGE = {
    "/manifest.json",
    "/repositories",
    "/blobs",
    "/oci-layout",
    "/index.json",
}


class ContainerImageLoader(Loader):
    """Load saved container images.

    Supports both the Docker and OCI image specifications.

    References:
        - https://snyk.io/blog/container-image-formats/
        - https://github.com/moby/docker-image-spec/
        - https://github.com/opencontainers/image-spec/
    """

    def __init__(self, path: TargetPath, **kwargs):
        super().__init__(path.resolve(), **kwargs)

        self.tar = None
        self.manifest = None
        self.name = None
        self.config = None

        try:
            self.tar = TarFilesystem(path.open("rb"))
        except Exception as e:
            raise ValueError(f"Unable to open {str(path)} as TarFilesystem: {str(e)}")

        try:
            self.manifest = json.loads(self.tar.path("/manifest.json").read_text())[0]
            self.name = self.manifest.get("RepoTags", [None])[0]
        except Exception as e:
            raise ValueError(f"Unable to read manifest.json inside docker image filesystem: {str(e)}")

        try:
            self.config = json.loads(self.tar.path(self.manifest.get("Config")).read_text())
        except Exception as e:
            raise ValueError(f"Unable to read config inside docker image filesystem: {str(e)}")

    @staticmethod
    def detect(path: TargetPath) -> bool:
        return (
            TarLoader.detect(path)
            and (root := set(map(str, TarFilesystem(path.open("rb")).path("/").iterdir())))
            and (OCI_IMAGE.issubset(root) or DOCKER_ARCHIVE_IMAGE.issubset(root))
        )

    def map(self, target: Target) -> None:
        fs = LayerFilesystem()

        for layer in [self.tar.path(p) for p in self.manifest.get("Layers", [])]:
            if not layer.exists():
                log.warning("Layer %s does not exist in container image", layer)
                continue

            fs.append_fs_layer(TarFilesystem(layer.open("rb")))

        fs.append_layer().mount("$fs$/container", self.tar)

        target.filesystems.add(fs)
