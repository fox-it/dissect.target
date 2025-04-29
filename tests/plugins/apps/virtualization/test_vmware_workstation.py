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
        ("target_win_users", "fs_win", "Users\\John\\AppData\\Local\\Temp\\VmwareDND"),
        ("target_unix_users", "fs_unix", "/home/user/.cache/vmware/drag_and_drop"),
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
