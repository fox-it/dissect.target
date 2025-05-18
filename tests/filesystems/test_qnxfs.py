from __future__ import annotations

import gzip
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.filesystems.qnxfs import QnxFilesystem, QnxFilesystemEntry
from tests._utils import absolute_path

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.mark.parametrize(
    "filename",
    [
        "_data/filesystems/qnxfs/qnx4.bin.gz",
        "_data/filesystems/qnxfs/qnx6-be.bin.gz",
        "_data/filesystems/qnxfs/qnx6-le.bin.gz",
    ],
)
def test_qnxfs_detect(filename: str) -> None:
    """Test that QNX filesystems are correctly detected."""
    with gzip.open(absolute_path(filename), "rb") as fh:
        assert QnxFilesystem.detect(fh)
        assert QnxFilesystem(fh).qnxfs


@pytest.fixture
def qnx_fs() -> Iterator[QnxFilesystem]:
    with patch("dissect.qnxfs.QNXFS", return_value=Mock(block_size=4096)):
        qnx_fs = QnxFilesystem(Mock())
        yield qnx_fs


@pytest.fixture
def qnxfs_fs_file_entry(qnx_fs: QnxFilesystem) -> Iterator[QnxFilesystemEntry]:
    inode = Mock(
        mode=0o100664,
        inum=4,
        size=165002,
        uid=1000,
        gid=999,
        atime=datetime(2024, 10, 1, 12, 0, 0, tzinfo=timezone.utc),
        mtime=datetime(2024, 10, 2, 12, 0, 0, tzinfo=timezone.utc),
        ctime=datetime(2024, 10, 3, 12, 0, 0, tzinfo=timezone.utc),
        ftime=datetime(2024, 10, 4, 12, 0, 0, tzinfo=timezone.utc),
        nlink=2,
        is_file=lambda: True,
        is_dir=lambda: False,
        is_symlink=lambda: False,
    )

    return QnxFilesystemEntry(qnx_fs, "/some_file", inode)


@pytest.mark.parametrize(
    ("entry_fixture", "expected_blocks"),
    [("qnxfs_fs_file_entry", 323)],
)
def test_qnxfs_stat(entry_fixture: str, expected_blocks: int, request: pytest.FixtureRequest) -> None:
    """Test consistency in ``stat()`` results."""
    qnxfs_entry: QnxFilesystemEntry = request.getfixturevalue(entry_fixture)
    stat = qnxfs_entry.stat()

    entry = qnxfs_entry.entry
    assert stat.st_mode == entry.mode
    assert stat.st_ino == entry.inum
    assert stat.st_dev == id(qnxfs_entry.fs)
    assert stat.st_nlink == entry.nlink
    assert stat.st_uid == entry.uid
    assert stat.st_gid == entry.gid
    assert stat.st_size == entry.size
    assert stat.st_atime == entry.atime.timestamp()
    assert stat.st_mtime == entry.mtime.timestamp()
    assert stat.st_ctime == entry.ctime.timestamp()
    assert stat.st_blksize == qnxfs_entry.fs.qnxfs.block_size
    assert stat.st_blocks == expected_blocks
