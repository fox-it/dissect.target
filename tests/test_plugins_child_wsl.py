from dissect.target.plugins.child.wsl import WSLTargetPlugin

from ._utils import absolute_path


def test_plugins_child_wsl(target_win_users, fs_win):

    vhdx_file = absolute_path("data/ext4.vhdx")
    fs_win.map_file(
        "users/john/appdata/local/Packages/CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc/LocalState/ext4.vhdx",
        vhdx_file,
    )

    target_win_users.add_plugin(WSLTargetPlugin)

    children = list(target_win_users.list_children())
    assert len(children) == 1
    assert children[0].type == "wsl"
    assert (
        children[0].path
        == "C:/Users/John/AppData/Local/Packages/CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc/LocalState/ext4.vhdx"  # noqa E501
    )

    child_targets = list(target_win_users.open_children())
    assert len(child_targets) == 1

    assert child_targets[0].hostname == "DESKTOP-123567"
    assert child_targets[0].os == "linux"
    assert child_targets[0].version == "Ubuntu 22.04.1 LTS (Jammy Jellyfish)"
    assert len(list(child_targets[0].users())) == 27
    assert list(child_targets[0].users())[-1].name == "user"
