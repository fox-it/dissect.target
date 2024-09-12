from unittest.mock import Mock

import pytest
from dissect.btrfs.btrfs import INode
from dissect.btrfs.c_btrfs import c_btrfs

from dissect.target.filesystems.btrfs import BtrfsFilesystemEntry


@pytest.mark.parametrize(
    "sector_size, filesize, expected_blocks",
    [
        (0x1000, 0x343, 0x1),
        (0x1000, 0x1000, 0x1),
        (0x1000, 0x1001, 0x2),
    ],
    ids=["lower", "equal", "greater"],
)
def test_stat_information_file_blocksize(sector_size: int, filesize: int, expected_blocks: int) -> None:
    entry = INode(Mock(), 42)
    entry.btrfs = Mock(sector_size=sector_size)
    timestamp = c_btrfs.btrfs_timespec()
    entry.inode = c_btrfs.btrfs_inode_item(
        mode=0o777,
        nlink=0,
        uid=1000,
        gid=1000,
        size=filesize,
        atime=timestamp,
        ctime=timestamp,
        otime=timestamp,
        mtime=timestamp,
    )

    fs_entry = BtrfsFilesystemEntry(Mock(), "some/path", entry)

    stat_info = fs_entry.lstat()

    assert stat_info.st_mode == 0o777
    assert stat_info.st_ino == 42
    assert stat_info.st_dev == 0
    assert stat_info.st_nlink == 0
    assert stat_info.st_uid == 1000
    assert stat_info.st_gid == 1000
    assert stat_info.st_size == filesize

    assert stat_info.st_atime == 0.0
    assert stat_info.st_atime_ns == 0
    assert stat_info.st_mtime == 0.0
    assert stat_info.st_mtime_ns == 0
    assert stat_info.st_ctime == 0.0
    assert stat_info.st_ctime_ns == 0
    assert stat_info.st_birthtime_ns == 0
    assert stat_info.st_birthtime_ns == 0

    assert stat_info.st_blksize == sector_size
    assert stat_info.st_blocks == expected_blocks
