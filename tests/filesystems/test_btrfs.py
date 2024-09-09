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
    entry = INode(Mock(), None)
    entry.btrfs = Mock(sector_size=sector_size)
    timestamp = c_btrfs.btrfs_timespec()
    entry.inode = c_btrfs.btrfs_inode_item(
        size=filesize, atime=timestamp, ctime=timestamp, otime=timestamp, mtime=timestamp
    )

    fs_entry = BtrfsFilesystemEntry(Mock(alt_seperator="/"), "unknown_path", entry)

    stat_info = fs_entry.lstat()

    assert stat_info.st_birthtime_ns == 0
    assert stat_info.st_blksize == sector_size
    assert stat_info.st_blocks == expected_blocks
