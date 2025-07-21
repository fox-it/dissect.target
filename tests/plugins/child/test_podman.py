from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.apps.container.podman import PodmanPlugin
from dissect.target.plugins.child.podman import PodmanChildTargetPlugin
from tests.plugins.apps.container.test_podman import target_unix_podman  # noqa: F401

if TYPE_CHECKING:
    from dissect.target import Target
    from dissect.target.filesystem import VirtualFilesystem


def test_plugins_child_podman(target_unix_podman: Target, fs_unix: VirtualFilesystem) -> None:  # noqa: F811
    """Test if we can find, parse and correctly yield child Podman targets."""

    target_unix_podman.add_plugin(PodmanPlugin)
    target_unix_podman.add_plugin(PodmanChildTargetPlugin)

    children = sorted(target_unix_podman.list_children(), key=lambda r: r.path)

    assert len(children) == 3
    assert children[0].type == "podman"

    assert sorted([c.path for c in children]) == [
        "/home/user/.local/share/containers/storage/overlay/04a40aded310ba9deffbd5b5b0120a0a4416e6083420e338e998250f1a2e2f2b",
        "/home/user/.local/share/containers/storage/overlay/5c2861226e61770d45f08a5bee9205c13c23221969d1fde7c3f4088f8aa1d46e",
        "/home/user/.local/share/containers/storage/overlay/f351129587e2bb1da9ba4f03dcd22e1c838cd4f20dcc70e6da72381d2905b913",
    ]
