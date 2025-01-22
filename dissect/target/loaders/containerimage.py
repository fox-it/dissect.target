from __future__ import annotations

from dissect.target.filesystems.containerimage import ContainerImageFilesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.loader import Loader
from dissect.target.loaders.tar import TarLoader
from dissect.target.target import Target

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
    """Load saved container images."""

    def __init__(self, path: TargetPath, **kwargs):
        super().__init__(path.resolve(), **kwargs)

    @staticmethod
    def detect(path: TargetPath) -> bool:
        return (
            TarLoader.detect(path)
            and (root := set(map(str, TarFilesystem(path.open("rb")).path("/").iterdir())))
            and (OCI_IMAGE.issubset(root) or DOCKER_ARCHIVE_IMAGE.issubset(root))
        )

    def map(self, target: Target) -> None:
        target.filesystems.add(ContainerImageFilesystem(self.path))
