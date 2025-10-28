from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.virtualization.vmware_workstation import (
    VmwareWorkstationPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("target", "fs", "dnd_path"),
    [
        pytest.param("target_win_users", "fs_win", "Users\\John\\AppData\\Local\\Temp\\VmwareDND", id="windows"),
        pytest.param("target_unix_users", "fs_unix", "/home/user/.cache/vmware/drag_and_drop", id="linux"),
    ],
)
def test_vmware_workstation_clipboard_dnd(
    target: Target, fs: VirtualFilesystem, dnd_path: str, request: pytest.FixtureRequest
) -> None:
    """Test if we correctly detect drag and drop artifacts on Windows and Unix targets."""

    target = request.getfixturevalue(target)
    fs = request.getfixturevalue(fs)
    fs.map_dir_from_tar(dnd_path, absolute_path("_data/plugins/apps/virtualization/vmware_workstation/dnd.tar"))
    target.add_plugin(VmwareWorkstationPlugin)
    results = sorted(target.vmware.clipboard(), key=lambda r: r.path)
    dnd_path = dnd_path.replace("\\", "/")

    assert len(results) == 3
    assert [str(r.path).replace("C:\\", "").replace("\\", "/") for r in results] == [
        f"{dnd_path}/8lkBf1/wachter.jpg",
        f"{dnd_path}/iUpQHG/credentials.txt",
        f"{dnd_path}/x1G9fJ/example.txt",
    ]
    assert results[0].ts == datetime(2024, 9, 18, 11, 16, 44, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("target", "fs", "inventory_dir"),
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
    ],
)
def test_vmware_workstation_vm_configs(
    target: Target, fs: VirtualFilesystem, inventory_dir: str, request: pytest.FixtureRequest
) -> None:
    """Test if we find and parse VM configuration files correctly."""

    target = request.getfixturevalue(target)
    fs = request.getfixturevalue(fs)
    fs.map_file(
        inventory_dir,
        str(absolute_path(f"_data/plugins/apps/virtualization/vmware_workstation/inventory-{target.os}.vmls")),
    )
    fs.map_file(
        "first.vmx" if target.os == "windows" else "/path/to/first.vmx",
        str(absolute_path("_data/plugins/apps/virtualization/vmware_workstation/first.vmx")),
    )

    target.add_plugin(VmwareWorkstationPlugin)

    records = list(target.vmware.config())

    assert len(records) == 3

    assert records[0].ts
    assert records[0].name == "First Virtual Machine"
    assert not records[0].is_clone
    assert not records[0].is_favorite
    assert records[0].state == "normal"
    assert records[0].uuid == "41cca13579fa4366abef2582d21a0c20"
    assert records[0].annotation == "This is an example annotation."
    assert records[0].mac_addresses == ["00:0C:29:12:34:56"]
    assert records[0].disks == ["First Virtual Machine.vmdk"]
    assert records[0].sources in (
        ["C:\\Users\\John\\AppData\\Roaming\\VMware\\inventory.vmls", "sysvol\\first.vmx"],
        ["/home/user/.vmware/inventory.vmls", "/path/to/first.vmx"],
    )
