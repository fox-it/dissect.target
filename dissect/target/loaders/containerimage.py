from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from dissect.target.filesystem import LayerFilesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.loaders.tar import TarSubLoader

if TYPE_CHECKING:
    import tarfile
    from pathlib import Path

    from dissect.target.target import Target

log = logging.getLogger(__name__)

DOCKER_ARCHIVE_IMAGE = {
    "manifest.json",
    "repositories",
}

OCI_IMAGE = {
    "blobs",
    "oci-layout",
    "index.json",
}


class ContainerImageTarSubLoader(TarSubLoader):
    """Load saved container images.

    Supports both the Docker and OCI image specifications.

    Tested with output from ``docker image save`` and ``podman image save``.

    References:
        - https://snyk.io/blog/container-image-formats/
        - https://github.com/moby/docker-image-spec/
        - https://github.com/opencontainers/image-spec/
    """

    def __init__(self, tar: tarfile.TarFile, *args, **kwargs):
        super().__init__(tar, *args, **kwargs)

        self.tarfs: TarFilesystem = None
        self.layers: list[Path] = []

        self.manifest = None
        self.name = None
        self.config = None

        try:
            self.tarfs = TarFilesystem(None, tarfile=tar)
        except Exception as e:
            raise ValueError(f"Unable to open {tar} as TarFilesystem: {e}") from e

        # Moby/Docker spec uses manifest.json
        if self.tarfs.path("/manifest.json").exists():
            try:
                self.manifest = json.loads(self.tarfs.path("/manifest.json").read_text())[0]
                self.name = self.manifest.get("RepoTags", [None])[0]
                self.layers = [self.tarfs.path(p) for p in self.manifest.get("Layers", [])]
            except Exception as e:
                raise ValueError(f"Unable to read manifest.json inside docker image filesystem: {e}") from e

            try:
                self.config = json.loads(self.tarfs.path(self.manifest.get("Config")).read_text())
            except Exception as e:
                raise ValueError(f"Unable to read config inside docker image filesystem: {e}") from e

        # OCI spec only has index.json
        elif self.tarfs.path("/index.json").exists():
            try:
                index = json.loads(self.tarfs.path("/index.json").read_text())
                self.config = json.loads(
                    self.tarfs.path("/blobs").joinpath(index["manifests"][0]["digest"].replace(":", "/")).read_text()
                )
                self.layers = [
                    self.tarfs.path("/blobs").joinpath(layer["digest"].replace(":", "/"))
                    for layer in self.config.get("layers", [])
                ]
            except Exception as e:
                raise ValueError(f"Unable to load OCI container: {e}") from e

    @staticmethod
    def detect(tar: tarfile.TarFile) -> bool:
        names = tar.getnames()
        return OCI_IMAGE.issubset(names) or DOCKER_ARCHIVE_IMAGE.issubset(names)

    def map(self, target: Target) -> None:
        fs = LayerFilesystem()

        for layer in self.layers:
            if not layer.exists():
                log.warning("Layer %s does not exist in container image", layer)
                continue

            fs.append_fs_layer(TarFilesystem(layer.open("rb")))

        fs.append_layer().mount("$fs$/container", self.tarfs)

        target.filesystems.add(fs)
