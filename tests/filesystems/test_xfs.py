from datetime import datetime
from typing import Iterator
from unittest.mock import Mock, patch

import pytest
from dissect.xfs.xfs import INode

from dissect.target.filesystems.xfs import XfsFilesystem, XfsFilesystemEntry


@pytest.fixture
def xfs_fs() -> Iterator[XfsFilesystem]:
    with patch("dissect.xfs.xfs.XFS", autospec=True):
        xfs_fs = XfsFilesystem(Mock())
        xfs_fs.xfs.block_size = 4096

        yield xfs_fs


@pytest.fixture
def xfs_fs_entry(xfs_fs: XfsFilesystem) -> Iterator[XfsFilesystemEntry]:
    mock_datetime = datetime(2023, 10, 1, 12, 0, 0)
    inode = Mock(
        spec=INode,
        number_of_blocks=10,
        inum=4,
        atime=mock_datetime,
        mtime=mock_datetime,
        ctime=mock_datetime,
        crtime=mock_datetime,
    )
    entry = XfsFilesystemEntry(xfs_fs, "/some_file", inode)
    yield entry


def test_es_filesystems_xfs_stat_blocks(xfs_fs: XfsFilesystem, xfs_fs_entry: XfsFilesystemEntry):
    stat = xfs_fs_entry.stat()

    assert stat.st_blocks == 10 * 4096 // 512
