from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.target.plugins.child.vmware_vcenter import (
    VmwareVcenterChildTargetPlugin,
)

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_child_vmware_vcenter(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we detect VMware vCenter children"""
    fs_unix.map_file_fh("/10.10.10.10-vm2026-01-07@00-00-00.tgz", BinaryIO())

    target_unix.add_plugin(VmwareVcenterChildTargetPlugin)
    children = [child for _, child in target_unix.list_children()]

    assert len(children) == 1
    assert children[0].type == "vmware_vcenter"
    assert children[0].path == "/10.10.10.10-vm2026-01-07@00-00-00.tgz"
