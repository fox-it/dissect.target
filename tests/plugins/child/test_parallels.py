from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.child.parallels import ParallelsChildTargetPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_parallels_child_detection(target_macos_users: Target, fs_macos: VirtualFilesystem) -> None:
    """Test if we correctly find Parallels child VMs on MacOS targets."""

    config = absolute_path("_data/plugins/child/parallels/config.pvs")
    fs_macos.map_file("Users/dissect/Parallels/Windows 11.pvm/config.pvs", config)
    fs_macos.map_file("Users/dissect/Documents/Parallels/Windows 10.pvm/config.pvs", config)
    fs_macos.map_file("Users/Shared/Parallels/Windows 7.pvm/config.pvs", config)
    fs_macos.map_file(
        "Users/dissect/Library/Group Containers/svn.com.parallels.desktop.appstore/Shared/Parallels/My VM.pvm/config.pvs",  # noqa: E501
        config,
    )

    target_macos_users.add_plugin(ParallelsChildTargetPlugin)
    children = [child for _, child in target_macos_users.list_children()]

    assert len(children) == 4

    assert children[0].type == "parallels"
    assert children[0].name == "My VM"
    assert children[0].path == "/Users/Shared/Parallels/Windows 7.pvm"

    assert children[1].type == "parallels"
    assert children[1].name == "My VM"
    assert children[1].path == "/Users/dissect/Parallels/Windows 11.pvm"

    assert children[2].type == "parallels"
    assert children[2].name == "My VM"
    assert children[2].path == "/Users/dissect/Documents/Parallels/Windows 10.pvm"

    assert children[3].type == "parallels"
    assert children[3].name == "My VM"
    assert (
        children[3].path
        == "/Users/dissect/Library/Group Containers/svn.com.parallels.desktop.appstore/Shared/Parallels/My VM.pvm"
    )
