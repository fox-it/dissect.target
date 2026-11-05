from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.child.dualboot import DualBootChildTargetPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_dualboot_win(target_win: Target) -> None:
    """Test if we detect dual boot child targets on a Windows target."""
    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc")
    fs.makedirs("opt")
    fs.map_file_fh("/etc/hostname", BytesIO(b"ubuntu"))
    target_win.filesystems.add(fs)

    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc/dpkg")
    fs.makedirs("opt")
    fs.map_file_fh("/etc/hostname", BytesIO(b"debian"))
    target_win.filesystems.add(fs)

    fs = VirtualFilesystem()
    fs.map_file_fh("/hello.txt", BytesIO(b"hello world!"))
    target_win.filesystems.add(fs)

    target_win.apply()
    target_win.add_plugin(DualBootChildTargetPlugin)
    children = sorted([child for _, child in target_win.list_children()], key=lambda r: r.path)

    assert len(children) == 2

    assert children[0].type == "dualboot_linux"
    assert children[0].name == "ubuntu"
    assert children[0].path == "/$fs$/fs0"

    assert children[1].type == "dualboot_linux"
    assert children[1].name == "debian"
    assert children[1].path == "/$fs$/fs1"


def test_dualboot_unix(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we detect dual boot child targets on a UNIX-like target."""
    fs = VirtualFilesystem()
    fs.makedirs("windows/system32/config")
    target_unix.filesystems.add(fs)

    fs = VirtualFilesystem()
    fs.makedirs("var")
    fs.makedirs("etc/dpkg")
    fs.makedirs("opt")
    fs.map_file_fh("/etc/hostname", BytesIO(b"debian"))
    target_unix.filesystems.add(fs)

    fs = VirtualFilesystem()
    fs.map_file_fh("/hello.txt", BytesIO(b"hello world!"))
    target_unix.filesystems.add(fs)

    target_unix.apply()
    target_unix.add_plugin(DualBootChildTargetPlugin)
    children = sorted([child for _, child in target_unix.list_children()], key=lambda r: r.path)

    assert len(children) == 2

    assert children[0].type == "dualboot_windows"
    assert children[0].name is None
    assert children[0].path == "/$fs$/fs0"

    assert children[1].type == "dualboot_linux"
    assert children[1].name == "debian"
    assert children[1].path == "/$fs$/fs1"
