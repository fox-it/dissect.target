from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.child.lima import LimaChildTargetPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_child_colima(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/root/.lima/default/diffdisk", BytesIO())
    fs_unix.map_file_fh("/root/.lima/docker/diffdisk", BytesIO())
    fs_unix.map_file_fh("/home/user/.config/lima/ligma/diffdisk", BytesIO())

    target_unix_users.add_plugin(LimaChildTargetPlugin)

    children = [child for _, child in target_unix_users.list_children()]

    assert len(children) == 3

    assert children[0].type == "lima"
    assert children[0].name == "default"
    assert children[0].path == "/root/.lima/default/diffdisk"

    assert children[1].name == "docker"
    assert children[1].path == "/root/.lima/docker/diffdisk"

    assert children[2].path == "/home/user/.config/lima/ligma/diffdisk"
