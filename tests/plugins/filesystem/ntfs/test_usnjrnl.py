from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugins.filesystem.ntfs.usnjrnl import UsnjrnlPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_usnjrnl_normal(target_win: Target) -> None:
    """Test parsing of a usnjrnl file."""
    filesystem = NtfsFilesystem(usnjrnl=absolute_path("_data/plugins/filesystem/ntfs/usnjrnl/usnjrnl.bin").open("rb"))
    target_win.filesystems = [filesystem]

    target_win.add_plugin(UsnjrnlPlugin)

    data = list(target_win.usnjrnl())

    assert len(data) == 15214
