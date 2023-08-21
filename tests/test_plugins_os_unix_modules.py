from dissect.target.plugins.os.unix.modules import ModulePlugin

from ._utils import absolute_path


def test_modules_plugin(target_unix, fs_unix):
    test_folder = absolute_path("data/plugins/os/unix/modules/module")
    fs_unix.map_dir("/sys/module", test_folder)

    target_unix.add_plugin(ModulePlugin)
    results = list(target_unix.modules())
    assert len(results) == 2
    assert results[0].name == "modulea"
    assert results[0].size == 1
    assert results[0].refcount == 3
    assert results[0].modules_referred == ["holdera"]
    assert results[1].name == "moduleb"
    assert results[1].size == 2
    assert results[1].refcount == 4
    assert results[1].modules_referred == ["holdera", "holderb"]
