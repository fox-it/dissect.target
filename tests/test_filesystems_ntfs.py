from unittest.mock import Mock, patch

import pytest
from dissect.ntfs.exceptions import FileNotFoundError as NtfsFileNotFoundError
from dissect.ntfs.util import AttributeMap

from dissect.target.exceptions import FileNotFoundError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.ntfs import NtfsFilesystem, NtfsFilesystemEntry


@pytest.mark.parametrize(
    "path, expected_path, expected_ads",
    [
        ("test:data", "test", "data"),
        ("test:$hello", "test", "$hello"),
        ("test:$hello:$test", "test:$hello", "$test"),
    ],
)
def test_ads_ntfs_filesystem(path, expected_path, expected_ads):
    with patch("dissect.target.filesystems.ntfs.NTFS"):
        filesystem = NtfsFilesystem()
        entry = filesystem.get(path)

        assert entry.ads == expected_ads
        assert entry.path == expected_path
        filesystem.ntfs.mft.get.assert_called_once_with(expected_path, root=None)


@pytest.mark.parametrize(
    "ads, name, output",
    [
        ("ads", "", "ads"),
        ("ads", "test", "test"),
    ],
)
def test_ntfs_fileentry_open(ads, name, output):
    vfs = VirtualFilesystem()
    mocked_entry = Mock()
    mocked_entry.attributes = AttributeMap()
    mocked_entry.is_dir.return_value = False
    entry = NtfsFilesystemEntry(vfs, "some/random/path", entry=mocked_entry)
    entry.ads = ads
    entry.open(name)

    mocked_entry.open.assert_called_once_with(output)


def test_ntfs_unknown_file():
    vfs = VirtualFilesystem()
    mocked_entry = Mock()
    mocked_entry.attributes = AttributeMap()
    mocked_entry.is_dir.return_value = False
    mocked_entry.size.side_effect = [NtfsFileNotFoundError]
    entry = NtfsFilesystemEntry(vfs, "some/random/path", entry=mocked_entry)
    with pytest.raises(FileNotFoundError):
        entry.stat()
