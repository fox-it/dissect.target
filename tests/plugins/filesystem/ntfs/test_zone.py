from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugins.filesystem.ntfs.mft import MftPlugin

from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target



@pytest.fixture
def target_win_mft(target_win: Target) -> Target:
    filesystem = NtfsFilesystem(mft=absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw").open("rb"))
    target_win.filesystems = [filesystem]
    target_win.add_plugin(MftPlugin)
    return target_win

def check_output_amount(number: int, compact_output: bool) -> int:
    more_records = (0 if compact_output else 1) * 3
    return number + number * more_records

def test_mft_plugin_entries(target_win_mft: Target) -> None:
    mft_data = list(target_win_mft.zone())
    assert len(mft_data) == check_output_amount(76, False)