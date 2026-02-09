from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows import adpolicy
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_adpolicy_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    policy_dir = absolute_path("_data/plugins/os/windows/adpolicy/")

    fs_win.map_dir("Windows/sysvol/domain/policies", policy_dir)

    target_win.add_plugin(adpolicy.ADPolicyPlugin)

    records = list(target_win.adpolicy())
    assert len(records) == 10
