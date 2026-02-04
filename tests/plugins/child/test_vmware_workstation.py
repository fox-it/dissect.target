from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.child.vmware_workstation import (
    VmwareWorkstationChildTargetPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("target_fixture", "fs_fixture", "inventory_path"),
    [
        pytest.param(
            "target_win_users",
            "fs_win",
            "Users\\John\\AppData\\Roaming\\VMware\\inventory.vmls",
            id="windows",
        ),
        pytest.param(
            "target_unix_users",
            "fs_unix",
            "/home/user/.vmware/inventory.vmls",
            id="linux",
        ),
        pytest.param(
            "target_macos_users",
            "fs_macos",
            "/Users/dissect/Library/Application Support/VMware Fusion/vmInventory",
            id="macos",
        ),
    ],
)
def test_child_vmware_workstation(
    target_fixture: str, fs_fixture: str, inventory_path: str, request: pytest.FixtureRequest
) -> None:
    """Test if we detect VMware Workstation children from inventory files correctly on Windows and Unix targets."""

    target: Target = request.getfixturevalue(target_fixture)
    fs: VirtualFilesystem = request.getfixturevalue(fs_fixture)

    fs.map_file(inventory_path, absolute_path("_data/plugins/child/vmware_workstation/inventory.vmls"))

    target.add_plugin(VmwareWorkstationChildTargetPlugin)
    children = [child for _, child in target.list_children()]

    assert len(children) == 3
    assert children[0].type == "vmware_workstation"
    assert children[0].name == "First Virtual Machine"
    assert children[0].path == "/path/to/first/vm/vm.vmx"

    assert [c.path for c in children] == [
        "/path/to/first/vm/vm.vmx",
        "/path/to/second/vm/vm.vmx",
        "/path/to/third/vm/vm.vmx",
    ]
