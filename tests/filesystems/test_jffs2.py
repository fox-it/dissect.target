from datetime import datetime
from typing import Iterator
from unittest.mock import Mock, patch
import pytest

from dissect.target.filesystems.jffs import JFFSFilesystem, JFFSFilesystemEntry


@pytest.fixture
def jffs_fs() -> Iterator[JFFSFilesystem]:
    with patch("dissect.jffs.jffs2.JFFS2"):
        jffs_fs = JFFSFilesystem(Mock())
        yield jffs_fs


@pytest.fixture
def jffs_fs_entry(jffs_fs: JFFSFilesystem) -> Iterator[JFFSFilesystemEntry]:
    raw_inode = Mock(uid=1000, guid=999, isize=165002)
    inode = Mock(
        mode=33204,
        inum=4,
        inode=raw_inode,
        atime=datetime(2024, 10, 1, 12, 0, 0),
        mtime=datetime(2024, 10, 2, 12, 0, 0),
        ctime=datetime(2024, 10, 3, 12, 0, 0),
    )

    entry = JFFSFilesystemEntry(jffs_fs, "/some_file", inode)
    yield entry


def test_jffs2(jffs_fs: JFFSFilesystem, jffs_fs_entry: JFFSFilesystemEntry) -> None:
    stat = jffs_fs_entry.stat()

    entry = jffs_fs_entry.entry
    assert stat.st_mode == entry.mode
    assert stat.st_ino == entry.inum
    assert stat.st_dev == id(jffs_fs)
    assert stat.st_nlink == 1
    assert stat.st_uid == entry.inode.uid
    assert stat.st_gid == entry.inode.gid
    assert stat.st_size == entry.inode.isize
    assert stat.st_atime == entry.atime.timestamp()
    assert stat.st_mtime == entry.mtime.timestamp()
    assert stat.st_ctime == entry.ctime.timestamp()
    assert stat.st_blksize == 4096
    assert stat.st_blocks == 323
