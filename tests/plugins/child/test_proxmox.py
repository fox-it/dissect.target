from __future__ import annotations

from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.child.proxmox import ProxmoxChildTargetPlugin
from dissect.target.plugins.os.unix.linux.debian.proxmox._os import ProxmoxPlugin
from dissect.target.target import Target


def test_proxmox_children() -> None:
    """Test that the Proxmox child target plugin lists children correctly."""
    vfs = VirtualFilesystem()
    vfs.map_file_fh("/etc/pve/qemu-server/100.conf", BytesIO(b"name: VM-100"))
    vfs.map_file_fh("/etc/pve/qemu-server/101.conf", BytesIO(b"name: VM-101"))

    target = Target()
    target._os_plugin = ProxmoxPlugin(target)
    target.filesystems.add(vfs)
    target.fs.mount("/", vfs)
    target.apply()

    target.add_plugin(ProxmoxChildTargetPlugin)

    children = [child for _, child in target.list_children()]

    assert len(children) == 2

    assert children[0].type == "proxmox"
    assert children[0].name == "VM-100"
    assert str(children[0].path) == "/etc/pve/qemu-server/100.conf"

    assert children[1].type == "proxmox"
    assert children[1].name == "VM-101"
    assert str(children[1].path) == "/etc/pve/qemu-server/101.conf"
