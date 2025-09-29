from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugins.filesystem.ntfs.zone import ZoneIdPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.fixture
def target_win_mft(target_win: Target) -> Target:
    filesystem = NtfsFilesystem(mft=absolute_path("_data/plugins/filesystem/ntfs/zone/zone.raw").open("rb"))
    target_win.filesystems = [filesystem]
    target_win.add_plugin(ZoneIdPlugin)
    return target_win


def test_mft_plugin_entries_count(target_win_mft: Target) -> None:
    # tests whether the correct number of entries are returned
    mft_data = list(target_win_mft.zone())
    assert len(mft_data) == 2


def test_mft_plugin_entries(target_win_mft: Target) -> None:
    # tests whether the returned info is correct
    mft_data = list(target_win_mft.zone())
    for entry in mft_data:
        filename = entry.file_path

        assert filename in ["ADS_ZoneValid.url", "BothAdsAndZone.zip"]

        if filename == "ADS_ZoneValid.url":
            assert entry.referrer_url == "https://github.com/fox-it/dissect.target.htm"
            assert entry.host_url == "https://github.com/fox-it/dissect.target.txt"
            assert entry.zone_id == 3
            assert entry.app_zone_id is None

        elif filename == "BothAdsAndZone.zip":
            assert entry.referrer_url == "https://docs.dissect.tools/en/stable/projects/dissect.target/index.html"
            assert entry.host_url == "https://docs.dissect.tools/en/stable/projects/dissect.target/index.docx"
            assert entry.zone_id == 4
            assert entry.last_writer is None
