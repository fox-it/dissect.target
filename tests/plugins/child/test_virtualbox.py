from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.child.virtualbox import VirtualBoxChildTargetPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_child_virtualbox_linux(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we detect Oracle VirtualBox children on a Linux target."""

    fs_unix.map_file(
        "/home/user/.config/VirtualBox/VirtualBox.xml",
        absolute_path("_data/plugins/child/virtualbox/VirtualBox.xml"),
    )

    # vbox to be found by traversing MachineRegistry values
    fs_unix.map_file_fh("/example/vms/example-vm/example-vm.vbox", BytesIO(b""))
    fs_unix.map_file_fh("/example/vms/second-vm/second-vm.vbox", BytesIO(b""))
    fs_unix.map_file_fh("/example/vms/third-vm/third-vm.vbox", BytesIO(b""))

    # vbox to be found by traversing SystemProperties defaultMachineFolder value
    fs_unix.map_file_fh("/some/other/folder/VirtualBox VMs/fourth-vm/fourth-vm.vbox", BytesIO(b""))

    # vbox to be found by traversing `$HOME/VirtualBox VMs` folders
    fs_unix.map_file_fh("/home/user/VirtualBox VMs/fifth-vm/fifth-vm.vbox", BytesIO(b""))

    # test deduplication by mapping the same VirtualBox.xml file for the root user
    fs_unix.map_file(
        "/root/.config/VirtualBox/VirtualBox.xml-prev",
        absolute_path("_data/plugins/child/virtualbox/VirtualBox.xml"),
    )

    target_unix_users.add_plugin(VirtualBoxChildTargetPlugin)
    children = list(target_unix_users.list_children())

    assert sorted(map(str, [child.path for child in children])) == [
        "/example/vms/example-vm/example-vm.vbox",
        "/example/vms/second-vm/second-vm.vbox",
        "/example/vms/third-vm/third-vm.vbox",
        "/home/user/VirtualBox VMs/fifth-vm/fifth-vm.vbox",
        "/some/other/folder/VirtualBox VMs/fourth-vm/fourth-vm.vbox",
    ]
