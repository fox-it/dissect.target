from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.child.colima import ColimaChildTargetPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_child_colima(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/root/.colima/default/colima.yaml", BytesIO())
    fs_unix.map_file_fh("/root/.colima/_lima/colima/diffdisk", BytesIO())
    fs_unix.map_file_fh("/root/.colima/test/colima.yaml", BytesIO())
    fs_unix.map_file_fh("/root/.colima/_lima/colima-test/diffdisk", BytesIO())
    fs_unix.map_file_fh("/home/user/.colima/default/colima.yaml", BytesIO())
    fs_unix.map_file_fh("/home/user/.colima/_lima/colima/diffdisk", BytesIO())

    target_unix_users.add_plugin(ColimaChildTargetPlugin)

    children = list(target_unix_users.list_children())

    assert len(children) == 3
    assert children[0].type == "colima"
    assert children[0].path == "/root/.colima/_lima/colima/diffdisk"
    assert children[1].path == "/root/.colima/_lima/colima-test/diffdisk"
    assert children[2].path == "/home/user/.colima/_lima/colima/diffdisk"
