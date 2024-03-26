from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.overlay import Overlay2Loader
from tests.plugins.apps.container.test_docker import (  # noqa: F401
    fs_docker,
    target_linux_docker,
)


def test_overlay_loader_docker_container(
    target_linux_docker: Target, fs_docker: VirtualFilesystem  # noqa: F811
) -> None:
    for container in target_linux_docker.fs.path("/var/lib/docker/image/overlay2/layerdb/mounts/").iterdir():
        assert Overlay2Loader.detect(container)
        loader = Overlay2Loader(container)
        loader.map(target_linux_docker)

    assert len(target_linux_docker.filesystems) == 4

    container_fs = target_linux_docker.filesystems[1]
    assert len(container_fs.layers) == 4
    assert len(list(container_fs.path("/").iterdir())) == 18
