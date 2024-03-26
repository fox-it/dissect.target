from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.child.docker import DockerChildTargetPlugin
from tests.plugins.apps.container.test_docker import (  # noqa: F401
    fs_docker,
    target_linux_docker,
)


def test_plugins_child_docker(target_linux_docker: Target, fs_docker: VirtualFilesystem) -> None:  # noqa: F811
    target_linux_docker.add_plugin(DockerChildTargetPlugin)
    children = list(target_linux_docker.list_children())

    assert len(children) == 3
    assert children[0].type == "docker"
    assert (
        children[0].path
        == "/var/lib/docker/image/overlay2/layerdb/mounts/f988f88e221d97930a665712cf16ab520f7e2c5af395660c145df93aebedf071"  # noqa
    )
