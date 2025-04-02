from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.child.parallels import ParallelsChildTargetPlugin
from dissect.target.target import Target


def test_parallels_child_detection(target_macos_users: Target, fs_macos: VirtualFilesystem) -> None:
    """test if we correctly find Parallels child VMs on MacOS targets."""

    fs_macos.makedirs("Users/dissect/Parallels/Windows 11.pvm")
    fs_macos.makedirs("Users/dissect/Documents/Parallels/Windows 10.pvm")
    fs_macos.makedirs(
        "Users/dissect/Library/Group Containers/someversionnumber.com.parallels.desktop.appstore/Shared/Parallels/Windows 8.pvm"  # noqa: E501
    )
    fs_macos.makedirs("Users/Shared/Parallels/Windows 7.pvm")

    target_macos_users.add_plugin(ParallelsChildTargetPlugin)
    children = list(target_macos_users.list_children())

    assert len(children) == 4
    assert [c.path for c in children] == [
        "/Users/Shared/Parallels/Windows 7.pvm",
        "/Users/dissect/Parallels/Windows 11.pvm",
        "/Users/dissect/Documents/Parallels/Windows 10.pvm",
        "/Users/dissect/Library/Group Containers/someversionnumber.com.parallels.desktop.appstore/Shared/Parallels/Windows 8.pvm",  # noqa: E501
    ]
