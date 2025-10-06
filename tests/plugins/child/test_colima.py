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
    fs_unix.map_file_fh("/home/user/.config/colima/default/colima.yaml", BytesIO())
    fs_unix.map_file_fh("/home/user/.config/colima/_lima/colima/diffdisk", BytesIO())

    target_unix_users.add_plugin(ColimaChildTargetPlugin)

    children = list(target_unix_users.list_children())

    assert len(children) == 3

    child_id, child_record = children[0]
    assert child_id == "0"
    assert child_record.type == "colima"
    assert child_record.name == "default"
    assert child_record.path == "/root/.colima/_lima/colima/diffdisk"

    child_id, child_record = children[1]
    assert child_id == "1"
    assert child_record.name == "test"
    assert child_record.path == "/root/.colima/_lima/colima-test/diffdisk"

    child_id, child_record = children[2]
    assert child_id == "2"
    assert child_record.path == "/home/user/.config/colima/_lima/colima/diffdisk"
