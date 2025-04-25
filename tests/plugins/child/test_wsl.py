from __future__ import annotations

import io
from typing import TYPE_CHECKING

from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
from dissect.target.plugins.child.wsl import WSLChildTargetPlugin

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_wsl(target_win_users: Target, hive_hku: VirtualHive, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file_fh(
        "users/john/appdata/local/Packages/CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc/LocalState/ext4.vhdx",
        io.BytesIO(),
    )

    wsl_keys_name = "Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"
    wsl_keys = VirtualKey(hive_hku, wsl_keys_name)

    wsl_key = VirtualKey(hive_hku, "{12345678-1234-1234-1234-123456789012}")
    wsl_key.add_value(
        "BasePath",
        VirtualValue(
            hive_hku,
            "BasePath",
            "C:\\Users\\John\\AppData\\Local\\Packages\\CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc\\LocalState",
        ),
    )

    wsl_keys.add_subkey(wsl_key.name, wsl_key)
    hive_hku.map_key(wsl_keys_name, wsl_keys)

    target_win_users.add_plugin(WSLChildTargetPlugin)

    children = list(target_win_users.list_children())
    assert len(children) == 1
    assert children[0].type == "wsl"
    assert (
        str(children[0].path)
        == "C:\\Users\\John\\AppData\\Local\\Packages\\CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc\\LocalState\\ext4.vhdx"  # noqa E501
    )
