from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.filesystems.xfs import XfsFilesystem, XfsFilesystemEntry

if TYPE_CHECKING:
    from collections.abc import Iterator

NANOSECONDS_IN_SECOND = 1_000_000_000


@pytest.fixture
def xfs_fs() -> Iterator[XfsFilesystem]:
    with patch("dissect.xfs.xfs.XFS"):
        xfs_fs = XfsFilesystem(Mock())
        xfs_fs.xfs.block_size = 4096

        yield xfs_fs


@pytest.fixture
def xfs_fs_entry(xfs_fs: XfsFilesystem) -> XfsFilesystemEntry:
    atime = datetime(2024, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
    mtime = datetime(2024, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    ctime = datetime(2024, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
    crtime = datetime(2024, 10, 4, 12, 0, 0, tzinfo=timezone.utc)

    dinode = Mock(di_mode=0o100750, di_nlink=1, di_uid=1000, di_gid=999)
    inode = Mock(
        nblocks=10,
        inode=dinode,
        inum=4,
        size=4594,
        atime=atime,
        atime_ns=atime.timestamp() * NANOSECONDS_IN_SECOND,
        mtime=mtime,
        mtime_ns=mtime.timestamp() * NANOSECONDS_IN_SECOND,
        ctime=ctime,
        ctime_ns=ctime.timestamp() * NANOSECONDS_IN_SECOND,
        crtime=crtime,
        crtime_ns=crtime.timestamp() * NANOSECONDS_IN_SECOND,
    )
    return XfsFilesystemEntry(xfs_fs, "/some_file", inode)


def test_xfs_stat(xfs_fs: XfsFilesystem, xfs_fs_entry: XfsFilesystemEntry) -> None:
    stat = xfs_fs_entry.stat()

    entry = xfs_fs_entry.entry
    assert stat.st_mode == entry.inode.di_mode
    assert stat.st_ino == entry.inum
    assert stat.st_dev == id(xfs_fs)
    assert stat.st_nlink == entry.inode.di_nlink
    assert stat.st_uid == entry.inode.di_uid
    assert stat.st_gid == entry.inode.di_gid
    assert stat.st_size == entry.size
    assert stat.st_atime == entry.atime.timestamp()
    assert stat.st_atime_ns == entry.atime_ns
    assert stat.st_mtime == entry.mtime.timestamp()
    assert stat.st_mtime_ns == entry.mtime_ns
    assert stat.st_ctime == entry.ctime.timestamp()
    assert stat.st_ctime_ns == entry.ctime_ns
    assert stat.st_birthtime == entry.crtime.timestamp()
    assert stat.st_birthtime_ns == entry.crtime_ns
    assert stat.st_blksize == 4096
    assert stat.st_blocks == 10 * 4096 // 512
