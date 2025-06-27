from datetime import datetime, timezone

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.windows.everything._plugin import EverythingPlugin
from dissect.target.target import Target
from tests._utils import absolute_path

DIRECTORY = "directory"
FILE = "file"


def test_everything_1_7_20_ntfs_only(target_win: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "\\Program Files\\Everything\\Everything.db",
        absolute_path("_data/plugins/os/windows/everything/1.7.20/Everything_NTFS_ONLY.db.gz"),
        compression="gzip",
    )
    target_win.add_plugin(EverythingPlugin)

    records = list(target_win.everything.locate())
    assert len(records) == 126828

    recycle_bin = records[0]
    assert recycle_bin.type == DIRECTORY
    assert recycle_bin.path == "C:\\$Recycle.Bin"
    assert recycle_bin.date_modified == datetime(2023, 12, 16, 9, 8, 42, 726189, tzinfo=timezone.utc)

    entry = records[-40000]
    assert entry.type == FILE
    assert entry.path == "C:\\Windows\\System32\\msidntld.dll"

    assert entry.date_modified == datetime(2021, 5, 8, 8, 14, 34, 642525, tzinfo=timezone.utc)


def test_everything_1_7_20_ntfs_and_folder(target_win: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "\\Program Files\\Everything\\Everything.db",
        absolute_path("_data/plugins/os/windows/everything/1.7.20/Everything_NTFS_AND_FOLDER.db.gz"),
        compression="gzip",
    )
    target_win.add_plugin(EverythingPlugin)

    records = list(target_win.everything.locate())
    assert len(records) == 127042
    recycle_bin_c = records[0]
    assert recycle_bin_c.type == DIRECTORY
    assert recycle_bin_c.path == "C:\\$Recycle.Bin"
    assert recycle_bin_c.date_modified == datetime(2023, 12, 16, 9, 8, 42, 726189, tzinfo=timezone.utc)

    recycle_bin_e = records[1]
    assert recycle_bin_e.type == DIRECTORY
    assert recycle_bin_e.path == "E:\\$RECYCLE.BIN"
    assert recycle_bin_e.date_modified == datetime(2024, 1, 27, 9, 54, 32, tzinfo=timezone.utc)

    entry = records[94783]
    assert entry.type == FILE
    assert entry.path == "E:\\potato.txt"
    assert entry.date_modified == datetime(2024, 1, 27, 9, 54, 32, tzinfo=timezone.utc)


def test_everything_1_7_20_ntfs_and_refs(target_win: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "\\Program Files\\Everything\\Everything.db",
        absolute_path("_data/plugins/os/windows/everything/1.7.20/Everything_NTFS_AND_REFS.db.gz"),
        compression="gzip",
    )
    target_win.add_plugin(EverythingPlugin)

    records = list(target_win.everything.locate())
    assert len(records) == 127227
    recycle_bin_c = records[0]
    assert recycle_bin_c.type == DIRECTORY
    assert recycle_bin_c.path == "C:\\$Recycle.Bin"
    assert recycle_bin_c.date_modified == datetime(2023, 12, 16, 9, 8, 42, 726189, tzinfo=timezone.utc)

    recycle_bin_e = records[1]
    assert recycle_bin_e.type == DIRECTORY
    assert recycle_bin_e.path == "E:\\$RECYCLE.BIN"
    assert recycle_bin_e.date_modified == datetime(2024, 1, 27, 21, 37, 6, 675776, tzinfo=timezone.utc)

    entry = records[94937]
    assert entry.type == FILE
    assert entry.path == "E:\\potato.txt"
    assert entry.date_modified == datetime(2024, 1, 27, 21, 37, 13, 425810, tzinfo=timezone.utc)

    entry = records[108011]
    assert entry.type == FILE
    assert entry.path == "E:\\test.txt"
    assert entry.date_modified == datetime(2024, 1, 27, 21, 56, 57, 597593, tzinfo=timezone.utc)


def test_everything_1_7_20_refs_with_disabled_ntfs(target_win: Target, fs_win: VirtualFilesystem) -> None:
    # Just making sure that disabling a drive doesn't mess up parsing
    fs_win.map_file(
        "\\Program Files\\Everything\\Everything.db",
        absolute_path("_data/plugins/os/windows/everything/1.7.20/Everything_REFS_WITH_DISABLED_NTFS.db.gz"),
        compression="gzip",
    )
    target_win.add_plugin(EverythingPlugin)

    records = list(target_win.everything.locate())
    assert len(records) == 7
    recycle_bin_e = records[0]
    assert recycle_bin_e.type == DIRECTORY
    assert recycle_bin_e.path == "E:\\$RECYCLE.BIN"
    assert recycle_bin_e.date_modified == datetime(2024, 1, 27, 21, 37, 6, 675776, tzinfo=timezone.utc)

    entry = records[5]
    assert entry.type == FILE
    assert entry.path == "E:\\potato.txt"
    assert entry.date_modified == datetime(2024, 1, 27, 21, 37, 13, 425810, tzinfo=timezone.utc)


def test_everything_1_7_20_refs_include_only(target_win: Target, fs_win: VirtualFilesystem) -> None:
    # Just making sure that including specific subfolders doesn't mess up parsing
    fs_win.map_file(
        "\\Program Files\\Everything\\Everything.db",
        absolute_path("_data/plugins/os/windows/everything/1.7.20/Everything_REFS_INCLUDE_ONLY.db.gz"),
        compression="gzip",
    )
    target_win.add_plugin(EverythingPlugin)

    records = list(target_win.everything.locate())
    assert len(records) == 4
    recycle_bin_e = records[0]
    assert recycle_bin_e.type == DIRECTORY
    assert recycle_bin_e.path == "E:\\test"
    assert recycle_bin_e.date_modified == datetime(2024, 1, 27, 22, 6, 9, 597820, tzinfo=timezone.utc)

    entry = records[3]
    assert entry.type == FILE
    assert entry.path == "E:\\test\\test.txt"
    assert entry.date_modified == datetime(2024, 1, 27, 21, 56, 57, 597593, tzinfo=timezone.utc)


def test_everything_1_7_20_efu(target_win: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "\\Program Files\\Everything\\Everything.db",
        absolute_path("_data/plugins/os/windows/everything/1.7.20/Everything_FILE_LIST.db.gz"),
        compression="gzip",
    )
    target_win.add_plugin(EverythingPlugin)

    records = list(target_win.everything.locate())
    assert len(records) == 5
    entry = records[0]
    assert entry.type == DIRECTORY
    assert entry.path == "E:"
    assert entry.date_modified is None

    entry = records[1]
    assert entry.type == DIRECTORY
    assert entry.path == "E:\\test"
    assert entry.date_modified == datetime(2024, 1, 27, 22, 6, 9, 597820, tzinfo=timezone.utc)


def test_everything_1_7_17_ntfs_refs_efu_folder(target_win: Target, fs_win: VirtualFilesystem) -> None:
    fs_win.map_file(
        "\\Program Files\\Everything\\Everything.db",
        absolute_path("_data/plugins/os/windows/everything/1.7.17/Everything_NTFS_REFS_EFU_FOLDER.db.gz"),
        compression="gzip",
    )
    target_win.add_plugin(EverythingPlugin)

    records = list(target_win.everything.locate())
    assert len(records) == 127577
    entry = records[0]
    assert entry.type == DIRECTORY
    assert entry.path == "C:\\$Recycle.Bin"
    assert entry.date_modified == datetime(2023, 12, 16, 9, 8, 42, 726189, tzinfo=timezone.utc)
    assert entry.date_created is None

    entry = records[1]
    assert entry.type == DIRECTORY
    assert entry.path == "C:\\$WinREAgent"
    assert entry.date_modified == datetime(2024, 1, 26, 20, 49, 55, 41714, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    "map_path",
    [
        "\\Program Files\\Everything\\Everything.db",
        "\\Program Files\\Everything\\Everything.COMPNAME.USERNAME.db",
        "\\Program Files (x86)\\Everything\\Everything.db",
        "\\Users\\John\\AppData\\Local\\Everything\\Everything.db",
        "\\Users\\John\\AppData\\Local\\Everything\\Everything.COMPNAME.John.db",
    ],
)
def test_everything_path_mapper(target_win_users: Target, fs_win: VirtualFilesystem, map_path: str) -> None:
    fs_win.map_file(
        map_path,
        absolute_path("_data/plugins/os/windows/everything/1.7.20/Everything_NTFS_ONLY.db.gz"),
        compression="gzip",
    )
    assert EverythingPlugin(target_win_users).check_compatible() is None
