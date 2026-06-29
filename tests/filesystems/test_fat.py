from __future__ import annotations

from io import BytesIO
from unittest.mock import Mock, create_autospec, patch

import pytest

from dissect.target.filesystems.fat import (
    FatFilesystem,
    FileNotFoundError,
    NotADirectoryError,
    fat_exc,
)


@pytest.mark.parametrize(
    ("raised_exception", "expected_exception"),
    [
        (fat_exc.FileNotFoundError, FileNotFoundError),
        (fat_exc.Error, FileNotFoundError),
        (fat_exc.NotADirectoryError, NotADirectoryError),
    ],
)
def test_get_entry(raised_exception: Exception, expected_exception: Exception) -> None:
    """Test whether the raised exception generates the expected exception."""
    mocked_fs = create_autospec(FatFilesystem)
    mocked_fs.fatfs = Mock()
    mocked_fs._get_entry = FatFilesystem._get_entry

    mocked_fs.fatfs.get.side_effect = [raised_exception]

    with pytest.raises(expected_exception):
        mocked_fs._get_entry(mocked_fs, path="")


def test_fat_identifier_no_guid() -> None:
    """FAT.identifier fallback using fatfs.volume_id when volume.guid is None."""
    dummy_fh = BytesIO(b"")  # empty in-memory file handle
    with patch("dissect.target.filesystems.fat.FatFilesystem.__init__", lambda self, fh: None):
        fs = FatFilesystem(fh=dummy_fh)
        fs.volume = Mock(guid=None)
        fs.fatfs = Mock(volume_id="1a2b3c4d")

        expected_uuid = "439041101"  # in decimal
        assert fs.identifier == expected_uuid
