import platform

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.modules import ModulePlugin
from dissect.target.target import Target

from ._utils import absolute_path


@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="Path mapping of test folder fails, module does not find any files",
)
def test_modules_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    test_folder = absolute_path("data/plugins/os/unix/linux/modules/module")
    fs_unix.map_dir("/sys/module", test_folder)

    target_unix.add_plugin(ModulePlugin)
    results = sorted(list(target_unix.sysmodules()), key=lambda x: x.name)
    assert len(results) == 2
    assert results[0].name == "modulea"
    assert results[0].size == 1
    assert results[0].refcount == 3
    assert results[0].used_by == ["holdera"]
    assert results[1].name == "moduleb"
    assert results[1].size == 2
    assert results[1].refcount == 4
    assert sorted(results[1].used_by) == ["holdera", "holderb"]
