from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.filesystems.ffs import FfsFilesystem, FfsFilesystemEntry

if TYPE_CHECKING:
    from collections.abc import Iterator

NANOSECONDS_IN_SECOND = 1_000_000_000


@pytest.fixture
def ffs_fs() -> Iterator[FfsFilesystem]:
    with patch("dissect.ffs.ffs.FFS"):
        ffs_fs = FfsFilesystem(Mock())
        ffs_fs.ffs.block_size = 32 * 1024
        yield ffs_fs


@pytest.fixture
def ffs_fs_entry(ffs_fs: FfsFilesystem) -> FfsFilesystemEntry:
    atime = datetime(2024, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
    mtime = datetime(2024, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    ctime = datetime(2024, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
    btime = datetime(2024, 10, 4, 12, 0, 0, tzinfo=timezone.utc)

    raw_inode = Mock(di_uid=1000, di_nlink=1, di_guid=999, di_size=165002)
    inode = Mock(
        mode=0o100664,
        inum=4,
        inode=raw_inode,
        nblocks=323,
        atime=atime,
        atime_ns=atime.timestamp() * NANOSECONDS_IN_SECOND,
        mtime=mtime,
        mtime_ns=mtime.timestamp() * NANOSECONDS_IN_SECOND,
        ctime=ctime,
        ctime_ns=ctime.timestamp() * NANOSECONDS_IN_SECOND,
        btime=btime,
        btime_ns=btime.timestamp() * NANOSECONDS_IN_SECOND,
        is_file=lambda: True,
        is_dir=lambda: False,
        is_symlink=lambda: False,
    )

    return FfsFilesystemEntry(ffs_fs, "/some_file", inode)


def test_jffs2_stat(ffs_fs_entry: FfsFilesystemEntry) -> None:
    stat = ffs_fs_entry.stat()

    entry = ffs_fs_entry.entry
    assert stat.st_mode == entry.mode
    assert stat.st_ino == entry.inum
    assert stat.st_dev == id(ffs_fs_entry.fs)
    assert stat.st_nlink == entry.inode.di_nlink
    assert stat.st_uid == entry.inode.di_uid
    assert stat.st_gid == entry.inode.di_gid
    assert stat.st_size == entry.inode.di_size
    assert stat.st_atime == entry.atime.timestamp()
    assert stat.st_mtime == entry.mtime.timestamp()
    assert stat.st_ctime == entry.ctime.timestamp()
    assert stat.st_birthtime == entry.btime.timestamp()
    assert stat.st_birthtime_ns == entry.btime_ns
    assert stat.st_blksize == 32 * 1024
    assert stat.st_blocks == 323
