from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugins.filesystem.icat import ICatPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_unsupported_fs(target_win: Target) -> None:
    # must not fail if sysvol mounted FS is not supported
    assert target_win.icat(1, 0, "") is None


def test_ntfs_fs(target_win: Target) -> None:
    mft_data_file = absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw")
    filesystem = NtfsFilesystem(mft=mft_data_file.open("rb"))
    target_win.filesystems = [filesystem]
    target_win.add_plugin(ICatPlugin)

    assert target_win.icat(1, 0, "") is None
