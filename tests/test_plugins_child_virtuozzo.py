from dissect.target.plugins.child.virtuozzo import VirtuozzoChildTargetPlugin


def test_plugins_child_virtuozzo(target_unix, fs_unix):
    fs_unix.makedirs("vz/root/a")
    fs_unix.makedirs("vz/root/b")

    target_unix.add_plugin(VirtuozzoChildTargetPlugin)

    children = list(target_unix.list_children())
    assert len(children) == 2
    assert children[0].type == "virtuozzo"
    assert str(children[0].path) == "/vz/root/a"
    assert children[1].type == "virtuozzo"
    assert str(children[1].path) == "/vz/root/b"
