from __future__ import annotations

import re
from random import randrange
from typing import TYPE_CHECKING
from unittest.mock import Mock

import pytest
from dissect.ntfs.c_ntfs import ATTRIBUTE_TYPE_CODE
from dissect.ntfs.exceptions import Error

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.plugins.filesystem.ntfs.mft import (
    FilesystemFilenameRecord,
    FilesystemStdRecord,
    MftPlugin,
    macb_aggregator,
)
from dissect.target.plugins.filesystem.ntfs.utils import (
    get_drive_letter,
    get_owner_and_group,
    get_volume_identifier,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target


@pytest.fixture(params=[True, False])
def compact(request: pytest.FixtureRequest) -> bool:
    return request.param


@pytest.fixture
def target_win_mft(target_win: Target) -> Target:
    filesystem = NtfsFilesystem(mft=absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw").open("rb"))
    target_win.filesystems = [filesystem]
    target_win.add_plugin(MftPlugin)
    return target_win


@pytest.mark.parametrize(
    ("drive_letters", "expected"),
    [
        (("z:", "c:", "a:"), "a:\\"),
        (("foo", "bar", "bla"), "bar\\"),
        (("$fs$\\fs2", "$fs$\\fs1", "$fs$\\fs0"), "$fs$\\fs0\\"),
        (("sysvol", "c:"), "c:\\"),
        (("sysvol", "c:", "a:"), "a:\\"),
        (("$fs$\\fs0", "sysvol", "c:"), "c:\\"),
        (("$fs$\\fs0", "sysvol"), "sysvol\\"),
        (("$fs$\\fs0",), "$fs$\\fs0\\"),
    ],
)
def test_driveletter(drive_letters: Iterator[str], expected: str) -> None:
    mocked_target = Mock()
    mocked_disk = Mock()
    num_drives = len(drive_letters)
    mocked_target.fs.mounts = dict(zip(drive_letters, [mocked_disk] * num_drives))

    assert get_drive_letter(mocked_target, mocked_disk) == expected


def test_driveletter_unknown() -> None:
    mocked_target = Mock()
    mocked_cdisk = Mock()
    mocked_target.fs.mounts = {"sysvol": mocked_cdisk, "c:": mocked_cdisk}
    assert get_drive_letter(mocked_target, Mock()) == ""


def test_driveletter_virtual_filesystems() -> None:
    mocked_target = Mock()
    mocked_ntfs = Mock()
    mock_fs = VirtualFilesystem()
    mock_fs.ntfs = mocked_ntfs
    mocked_ntfs_fs = Mock(spec=NtfsFilesystem)
    mocked_ntfs_fs.ntfs = mocked_ntfs
    mocked_target.fs.mounts = {"sysvol": VirtualFilesystem(), "c:": mock_fs}
    assert get_drive_letter(mocked_target, mocked_ntfs_fs) == "c:\\"


@pytest.mark.parametrize(
    "exception",
    [
        Error,
        AttributeError,
        KeyError,
        TypeError,
    ],
)
def test_get_owner_and_group_fail(exception: Exception) -> None:
    mocked_fs = Mock()
    mocked_fs.ntfs.secure.lookup.side_effect = [exception]

    mocked_entry = Mock()
    mocked_entry.attributes = {ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION: [Mock()]}
    assert get_owner_and_group(mocked_entry, mocked_fs) == (None, None)


def test_get_owner_and_group_none_attr() -> None:
    mocked_entry = Mock()
    mocked_entry.attributes = {ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION: [None]}
    assert get_owner_and_group(mocked_entry, Mock()) == (None, None)


@pytest.mark.parametrize(
    ("guid_bytes", "expected_result"),
    [
        (b",\xa6\xc1}\x88\xc4\xc5G\x8e\xab\t$\x0f8\x89N", "7dc1a62c-c488-47c5-8eab-09240f38894e"),
        (b"", None),
        (None, None),
    ],
)
def test_volume_identifier(guid_bytes: bytes, expected_result: str | None) -> None:
    filesystem = Mock()
    filesystem.volume.guid = guid_bytes
    assert get_volume_identifier(filesystem) == expected_result


def test_volume_identifier_no_volume() -> None:
    filesystem = Mock()
    filesystem.volume = None
    assert get_volume_identifier(filesystem) is None


def test_volume_identifier_none_guid() -> None:
    filesystem = Mock()
    filesystem.volume.guid = None
    assert get_volume_identifier(filesystem) is None


@pytest.mark.parametrize(
    ("regex_pattern", "expected_nr_of_records"),
    [
        (r".*", 304),
        (r".+Size:(No Data)", 120),
        (r".+Is_ADS$", 24),
        (r".+Size:\d+", 184),
        (
            r"2021-08-04 ([+.:]?\d+)+ [SF]0?[BCMA] 43 NamelessDirectory - "
            r"In[uU]se:True Resident:No Data Owner:No Data Size:No Data VolumeUUID:No Data",
            8,
        ),
        (
            r"2021-08-04 ([+.:]?\d+)+ [SF]0?[BCMA] 46 NamelessDirectory\\totally_normal.txt - "
            r"In[uU]se:True Resident:True Owner:No Data Size:28 VolumeUUID:No Data",
            8,
        ),
        (
            r"2021-08-04 ([+.:]?\d+)+ [SF]0?[BCMA] 46 NamelessDirectory\\totally_normal.txt"
            r":secret_text.txt - InUse:True Resident:True Owner:No Data Size:24 VolumeUUID:No Data Is_ADS",
            4,
        ),
    ],
)
def test_mft_timeline(target_win_mft: Target, regex_pattern: str, expected_nr_of_records: int) -> None:
    """Test whether the MFT timeline functions as inteded, same with the output."""
    outputs = [entry for entry in target_win_mft.mft.timeline() if re.match(regex_pattern, entry)]

    # Check the MFT entries
    assert len(outputs) == expected_nr_of_records


def check_output_amount(number: int, compact_output: bool) -> int:
    more_records = (0 if compact_output else 1) * 3
    return number + number * more_records


def test_mft_plugin_entries(target_win_mft: Target, compact: bool) -> None:
    mft_data = list(target_win_mft.mft(compact))
    assert len(mft_data) == check_output_amount(76, compact)


def test_mft_plugin_macb(target_win_mft: Target) -> None:
    mft_data = list(target_win_mft.mft(macb=True))
    path = None
    ts = None
    macb = None
    field = "MACB/MACB"
    for record in mft_data:
        assert record.macb != macb or record.ts != ts or record.path != path
        for bit in [0, 1, 2, 3, 5, 6, 7]:
            assert record.macb[bit : bit + 1] in (field[bit : bit + 1], ".")
        path = record.path
        macb = record.macb
        ts = record.ts


def test_mft_plugin_macb_ads(target_win_mft: Target) -> None:
    mft_data = list(target_win_mft.mft(macb=True))
    ads_entries = 0
    for record in mft_data:
        if record.ads:
            ads_entries += 1
            assert record.macb.endswith("/....")
            assert not record.macb.startswith("..../")
    assert ads_entries == 6


def test_mft_plugin_macb_nodup() -> None:
    # test whether you can never have duplicates

    def make_ts(tss: set) -> int:
        ts = randrange(1, 10)
        tss.add(ts)
        return ts

    for _ in range(100):
        tss = set()
        records = []
        for ts_type in ["M", "A", "C", "B"]:
            records.append(FilesystemStdRecord(path="a.txt", ts=make_ts(tss), ts_type=ts_type))
            records.append(FilesystemFilenameRecord(path="a.txt", ts=make_ts(tss), ts_type=ts_type, ads=False))
            records.append(FilesystemFilenameRecord(path="a.txt", ts=make_ts(tss), ts_type=ts_type, ads=True))
        assert len(list(macb_aggregator(records))) == len(tss)


def test_mft_plugin_disk_label(target_win_mft: Target) -> None:
    target_win_mft.fs.mounts = {"c:": target_win_mft.filesystems[0]}
    for mft_entries in target_win_mft.mft():
        assert str(mft_entries.path).startswith("c:\\")


def test_mft_plugin_ads(target_win_mft: Target, compact: bool) -> None:
    mft_data = [mft_entry for mft_entry in target_win_mft.mft(compact) if hasattr(mft_entry, "ads") and mft_entry.ads]
    assert len(mft_data) == check_output_amount(6, compact)


def test_mft_plugin_resident(target_win_mft: Target, compact: bool) -> None:
    mft_data = [mft_entry for mft_entry in target_win_mft.mft(compact) if mft_entry.resident]
    assert len(mft_data) == check_output_amount(19, compact)


def test_mft_plugin_inuse(target_win_mft: Target, compact: bool) -> None:
    mft_data = [mft_entry for mft_entry in target_win_mft.mft(compact) if mft_entry.inuse]
    assert len(mft_data) == check_output_amount(76, compact)


def test_mft_plugin_last_entries(target_win_mft: Target) -> None:
    mft_data = list(target_win_mft.mft())[-9:]
    test_data = [
        "NamelessDirectory",
        "Food For Thought",
        "text_document.txt",
        "NamelessDirectory\\totally_normal.txt",
        "NamelessDirectory\\totally_normal.txt:secret_text.txt",
    ]
    for mft_entry in mft_data:
        assert str(mft_entry.path) in test_data


def test_mft_plugin_owner(target_win_mft: Target) -> None:
    for mft_entry in target_win_mft.mft():
        assert mft_entry.owner is None
