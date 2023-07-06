import io

from dissect.target.helpers.regutil import VirtualKey, VirtualValue
from dissect.target.plugins.child.wsl import WSLChildTargetPlugin


def test_plugins_child_wsl(target_win_users, hive_hku, fs_win):
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
