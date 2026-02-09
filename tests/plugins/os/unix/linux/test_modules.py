from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.modules import ModulePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_modules_plugin(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    test_folder = absolute_path("_data/plugins/os/unix/linux/modules/module")
    fs_unix.map_dir("/sys/module", test_folder)

    target_unix.add_plugin(ModulePlugin)
    results = sorted(target_unix.sysmodules(), key=lambda x: x.name)
    assert len(results) == 2
    assert results[0].name == "modulea"
    assert results[0].size == 1
    assert results[0].refcount == 3
    assert results[0].used_by == ["holdera"]
    assert results[1].name == "moduleb"
    assert results[1].size == 2
    assert results[1].refcount == 4
    assert sorted(results[1].used_by) == ["holdera", "holderb"]
