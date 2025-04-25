from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.loaders.overlay import Overlay2Loader

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_overlay_loader_docker(target_linux_docker: Target) -> None:
    for container in target_linux_docker.fs.path("/var/lib/docker/image/overlay2/layerdb/mounts/").iterdir():
        assert Overlay2Loader.detect(container)
        loader = Overlay2Loader(container)
        loader.map(target_linux_docker)

    assert len(target_linux_docker.filesystems) == 4

    container_fs = target_linux_docker.filesystems[1]
    assert len(container_fs.layers) == 4
    assert len(list(container_fs.path("/").iterdir())) == 18
