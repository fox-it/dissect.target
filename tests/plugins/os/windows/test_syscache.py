from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugins.os.windows.syscache import SyscachePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_syscache_plugin(target_win: Target, fs_win: VirtualFilesystem) -> None:
    syscache_file = absolute_path("_data/plugins/os/windows/syscache/Syscache.hve")
    fs_win.map_file("System Volume Information/Syscache.hve", syscache_file)

    target_win.add_plugin(SyscachePlugin)

    results = list(target_win.syscache())
    assert len(results) == 401


def test_syscache_plugin_real_mft(target_win: Target, fs_win: VirtualFilesystem) -> None:
    filesystem = NtfsFilesystem(mft=absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw").open("rb"))

    # We need to change the type of the mocked filesystem, since syscache.py checks for explicit value
    target_win.fs.mounts["sysvol"].__type__ = "ntfs"
    target_win.fs.mounts["sysvol"].ntfs = filesystem.ntfs

    syscache_file = absolute_path("_data/plugins/os/windows/syscache/Syscache-mft.hve")
    fs_win.map_file("System Volume Information/Syscache.hve", syscache_file)

    target_win.add_plugin(SyscachePlugin)

    results = list(target_win.syscache())
    assert len(results) == 401

    filepaths = [entry.path for entry in results]
    assert filepaths.count(None) == 399
    assert "sysvol\\NamelessDirectory\\totally_normal.txt" in filepaths
    assert "sysvol\\text_document.txt" in filepaths
