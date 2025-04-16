from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.child.virtuozzo import VirtuozzoChildTargetPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_virtuozzo(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.makedirs("vz/root/a")
    fs_unix.makedirs("vz/root/b")

    target_unix.add_plugin(VirtuozzoChildTargetPlugin)

    children = list(target_unix.list_children())
    assert len(children) == 2
    assert children[0].type == "virtuozzo"
    assert str(children[0].path) == "/vz/root/a"
    assert children[1].type == "virtuozzo"
    assert str(children[1].path) == "/vz/root/b"
