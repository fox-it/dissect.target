from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.child.containerd import ContainerdChildTargetPlugin
from tests.plugins.apps.container.test_containerd import target_unix_containerd_docker  # noqa: F401

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_containerd(target_unix_containerd_docker: Target) -> None:  # noqa: F811
    target_unix_containerd_docker.add_plugin(ContainerdChildTargetPlugin)
    children = sorted([child for _, child in target_unix_containerd_docker.list_children()], key=lambda r: r.path)

    assert len(children) == 1
    assert children[0].type == "containerd"
    assert children[0].name is None
    assert (
        children[0].path
        == "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db/5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181"  # noqa: E501
    )
