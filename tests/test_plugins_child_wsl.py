import io

from dissect.target.plugins.child.wsl import WSLChildTargetPlugin


def test_plugins_child_wsl(target_win_users, fs_win):
    fs_win.map_file_fh(
        "users/john/appdata/local/Packages/CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc/LocalState/ext4.vhdx",
        io.BytesIO(),
    )

    target_win_users.add_plugin(WSLChildTargetPlugin)

    children = list(target_win_users.list_children())
    assert len(children) == 1
    assert children[0].type == "wsl"
    assert (
        str(children[0].path)
        == "C:/Users/John/AppData/Local/Packages/CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc/LocalState/ext4.vhdx"  # noqa E501
    )
