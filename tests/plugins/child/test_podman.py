from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.container.podman import PodmanPlugin
from dissect.target.plugins.child.podman import PodmanChildTargetPlugin
from tests.plugins.apps.container.test_podman import target_unix_podman  # noqa: F401


def test_plugins_child_podman(target_unix_podman: Target, fs_unix: VirtualFilesystem) -> None:  # noqa: F811
    """test if we can find, parse and correctly yield child Podman targets."""

    target_unix_podman.add_plugin(PodmanPlugin)
    target_unix_podman.add_plugin(PodmanChildTargetPlugin)

    children = sorted(list(target_unix_podman.list_children()), key=lambda r: r.path)

    assert len(children) == 3
    assert children[0].type == "podman"

    assert sorted([c.path for c in children]) == [
        "/home/user/.local/share/containers/storage/overlay/04a40aded310ba9deffbd5b5b0120a0a4416e6083420e338e998250f1a2e2f2b",  # noqa: E501
        "/home/user/.local/share/containers/storage/overlay/5c2861226e61770d45f08a5bee9205c13c23221969d1fde7c3f4088f8aa1d46e",  # noqa: E501
        "/home/user/.local/share/containers/storage/overlay/f351129587e2bb1da9ba4f03dcd22e1c838cd4f20dcc70e6da72381d2905b913",  # noqa: E501
    ]
