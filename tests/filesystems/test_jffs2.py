from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.filesystems.jffs import JffsFilesystem, JffsFilesystemEntry

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def jffs_fs() -> Iterator[JffsFilesystem]:
    with patch("dissect.jffs.jffs2.JFFS2"):
        jffs_fs = JffsFilesystem(Mock())
        yield jffs_fs


@pytest.fixture
def jffs_fs_file_entry(jffs_fs: JffsFilesystem) -> JffsFilesystemEntry:
    raw_inode = Mock(uid=1000, guid=999, isize=165002)
    inode = Mock(
        mode=0o100664,
        inum=4,
        nlink=1,
        inode=raw_inode,
        atime=datetime(2024, 10, 1, 12, 0, 0, tzinfo=timezone.utc),
        mtime=datetime(2024, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
        ctime=datetime(2024, 10, 3, 12, 0, 0, tzinfo=timezone.utc),
        is_file=lambda: True,
        is_dir=lambda: False,
        is_symlink=lambda: False,
    )

    return JffsFilesystemEntry(jffs_fs, "/some_file", inode)


@pytest.fixture
def jffs_fs_directory_entry(jffs_fs: JffsFilesystem) -> JffsFilesystemEntry:
    raw_inode = Mock(uid=1000, guid=999, isize=0)
    inode = Mock(
        mode=0o40775,
        inum=2,
        nlink=2,
        inode=raw_inode,
        atime=datetime(2024, 10, 1, 12, 0, 0, tzinfo=timezone.utc),
        mtime=datetime(2024, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
        ctime=datetime(2024, 10, 3, 12, 0, 0, tzinfo=timezone.utc),
        is_file=lambda: False,
        is_dir=lambda: True,
        is_symlink=lambda: False,
    )

    return JffsFilesystemEntry(jffs_fs, "/some_directory", inode)


@pytest.mark.parametrize(
    ("entry_fixture", "expected_blocks"), [("jffs_fs_file_entry", 323), ("jffs_fs_directory_entry", 0)]
)
def test_jffs2_stat(entry_fixture: str, expected_blocks: int, request: pytest.FixtureRequest) -> None:
    jffs_entry: JffsFilesystemEntry = request.getfixturevalue(entry_fixture)
    stat = jffs_entry.stat()

    entry = jffs_entry.entry
    assert stat.st_mode == entry.mode
    assert stat.st_ino == entry.inum
    assert stat.st_dev == id(jffs_entry.fs)
    assert stat.st_nlink == entry.nlink
    assert stat.st_uid == entry.inode.uid
    assert stat.st_gid == entry.inode.gid
    assert stat.st_size == entry.inode.isize
    assert stat.st_atime == entry.atime.timestamp()
    assert stat.st_mtime == entry.mtime.timestamp()
    assert stat.st_ctime == entry.ctime.timestamp()
    assert stat.st_blksize == 4096
    assert stat.st_blocks == expected_blocks
