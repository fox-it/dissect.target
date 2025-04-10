from __future__ import annotations

import io
import math
from unittest.mock import Mock, patch

import pytest
from dissect.ntfs.attr import Attribute, StandardInformation
from dissect.ntfs.c_ntfs import c_ntfs
from dissect.ntfs.exceptions import FileNotFoundError as NtfsFileNotFoundError
from dissect.ntfs.mft import MftRecord
from dissect.ntfs.util import AttributeMap

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.ntfs import NtfsFilesystem, NtfsFilesystemEntry


@pytest.mark.parametrize(
    ("path", "expected_path", "expected_ads"),
    [
        ("test:data", "test", "data"),
        ("test:$hello", "test", "$hello"),
        ("test:$hello:$test", "test:$hello", "$test"),
    ],
)
def test_ads_ntfs_filesystem(path: str, expected_path: str, expected_ads: str) -> None:
    with patch("dissect.target.filesystems.ntfs.NTFS"):
        filesystem = NtfsFilesystem()
        entry = filesystem.get(path)

        assert entry.ads == expected_ads
        assert entry.path == expected_path
        filesystem.ntfs.mft.get.assert_called_once_with(expected_path, root=None)


@pytest.mark.parametrize(
    ("ads", "name", "output"),
    [
        ("ads", "", "ads"),
        ("ads", "test", "test"),
    ],
)
def test_ntfs_fileentry_open(ads: str, name: str, output: str) -> None:
    vfs = VirtualFilesystem()
    mocked_entry = Mock()
    mocked_entry.attributes = AttributeMap()
    mocked_entry.is_dir.return_value = False
    mocked_entry.is_symlink.return_value = False
    mocked_entry.is_mount_point.return_value = False
    entry = NtfsFilesystemEntry(vfs, "some/random/path", entry=mocked_entry)
    entry.ads = ads
    entry.open(name)

    mocked_entry.open.assert_called_once_with(output)


def test_ntfs_unknown_file() -> None:
    vfs = VirtualFilesystem()
    mocked_entry = Mock()
    mocked_entry.attributes = AttributeMap()
    mocked_entry.is_dir.return_value = False
    mocked_entry.is_symlink.return_value = False
    mocked_entry.is_mount_point.return_value = False
    mocked_entry.size.side_effect = [NtfsFileNotFoundError]
    entry = NtfsFilesystemEntry(vfs, "some/random/path", entry=mocked_entry)
    with pytest.raises(FileNotFoundError):
        entry.stat()


@pytest.mark.parametrize(
    ("cluster_size", "size", "resident", "expected_blks"),
    [
        (0x1000, 0x343, False, 8),
        (0x1000, 0x1001, False, 16),
        (0x1000, 0, False, 0),
        (0x1000, 0x2000, True, 0),
    ],
)
def test_stat_information(cluster_size: int, size: int, resident: bool, expected_blks: int) -> None:
    ntfs = Mock(cluster_size=cluster_size)

    entry = MftRecord()
    entry.header = c_ntfs._FILE_RECORD_SEGMENT_HEADER()
    entry.ntfs = ntfs
    entry.segment = 42

    attribute_record = c_ntfs._ATTRIBUTE_RECORD_HEADER()
    attribute_record.FormCode = 0 if resident else 1
    if resident:
        attribute_record.Form.Resident.ValueLength = size
    else:
        attribute_record.Form.Nonresident.FileSize = size
        # Needs to be a multiple of cluster_size
        attribute_record.Form.Nonresident.AllocatedLength = math.ceil(size / cluster_size) * cluster_size

    map = AttributeMap()
    map[0x10] = StandardInformation(
        io.BytesIO(
            b"\xb5\xc3S\xbb\xd1a\xd8\x01\xc1H\xedc$\x04\xdb\x01d \x0c\xb0v\xcc\xd9"
            b"\x01\xc1H\xedc$\x04\xdb\x01 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00%\x03\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x92h8\x00\x00\x00\x00"
        )
    )
    map[0x80] = [Attribute.from_fh(io.BytesIO(attribute_record.dumps()))]

    mock_fs = Mock()
    with patch.object(entry, "attributes", map):
        fs_entry = NtfsFilesystemEntry(mock_fs, "some/path", entry)

        stat_info = fs_entry.lstat()

        assert stat_info.st_mode == 33279
        assert stat_info.st_ino == 42
        assert stat_info.st_dev == id(mock_fs)
        assert stat_info.st_nlink == 0
        assert stat_info.st_uid == 0
        assert stat_info.st_gid == 0
        assert stat_info.st_size == size

        assert stat_info.st_atime == 1726043227.939039
        assert stat_info.st_atime_ns == 1726043227939040100
        assert stat_info.st_mtime == 1726043227.939039
        assert stat_info.st_mtime_ns == 1726043227939040100
        assert stat_info.st_ctime == 1651900642.631773
        assert stat_info.st_ctime_ns == 1651900642631774900
        assert stat_info.st_birthtime == 1651900642.631773
        assert stat_info.st_birthtime_ns == 1651900642631774900

        assert stat_info.st_blksize == cluster_size
        assert stat_info.st_blocks == expected_blks
