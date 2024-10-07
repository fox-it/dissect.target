from dissect.target import Target
from dissect.target.plugins.child.docker import DockerChildTargetPlugin


def test_plugins_child_docker(target_linux_docker: Target) -> None:
    target_linux_docker.add_plugin(DockerChildTargetPlugin)
    children = sorted(list(target_linux_docker.list_children()), key=lambda r: r.path)

    assert len(children) == 3
    assert children[0].type == "docker"

    assert [c.path for c in children] == [
        "/var/lib/docker/image/overlay2/layerdb/mounts/01b646bc043eb4ad72f3a64b4ffd9be2cbeb399e0a07497d749d724460ccad3a",  # noqa: E501
        "/var/lib/docker/image/overlay2/layerdb/mounts/589135d12011921ac6ce69753569da5f206f4bc792a9133727ddae860997ee66",  # noqa: E501
        "/var/lib/docker/image/overlay2/layerdb/mounts/f988f88e221d97930a665712cf16ab520f7e2c5af395660c145df93aebedf071",  # noqa: E501
    ]
