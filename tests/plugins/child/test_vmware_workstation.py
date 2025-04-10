import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.child.vmware_workstation import (
    VmwareWorkstationChildTargetPlugin,
)
from dissect.target.target import Target
from tests._utils import absolute_path


@pytest.mark.parametrize(
    "target,fs,inventory_path",
    [
        ("target_win_users", "fs_win", "Users\\John\\AppData\\Roaming\\VMware\\inventory.vmls"),
        ("target_unix_users", "fs_unix", "/home/user/.vmware/inventory.vmls"),
    ],
)
def test_child_vmware_workstation(
    target: Target, fs: VirtualFilesystem, inventory_path: str, request: pytest.FixtureRequest
) -> None:
    """test if we detect VMware Workstation children from inventory files correctly on Windows and Unix targets"""

    target = request.getfixturevalue(target)
    fs = request.getfixturevalue(fs)

    fs.map_file(inventory_path, absolute_path("_data/plugins/child/vmware_workstation/inventory.vmls"))
    target.add_plugin(VmwareWorkstationChildTargetPlugin)
    children = list(target.list_children())

    assert len(children) == 3
    assert [c.path for c in children] == [
        "/path/to/first/vm/vm.vmx",
        "/path/to/second/vm/vm.vmx",
        "/path/to/third/vm/vm.vmx",
    ]
