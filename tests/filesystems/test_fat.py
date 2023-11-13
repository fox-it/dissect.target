from unittest.mock import Mock, create_autospec

import pytest

from dissect.target.filesystems.fat import (
    FatFilesystem,
    FileNotFoundError,
    NotADirectoryError,
    fat_exc,
)


@pytest.mark.parametrize(
    "raised_exception, expected_exception",
    [
        (fat_exc.FileNotFoundError, FileNotFoundError),
        (fat_exc.Error, FileNotFoundError),
        (fat_exc.NotADirectoryError, NotADirectoryError),
    ],
)
def test_get_entry(raised_exception, expected_exception):
    """Test whether the raised exception generates the expected exception."""
    mocked_fs = create_autospec(FatFilesystem)
    mocked_fs.fatfs = Mock()
    mocked_fs._get_entry = FatFilesystem._get_entry

    mocked_fs.fatfs.get.side_effect = [raised_exception]

    with pytest.raises(expected_exception):
        mocked_fs._get_entry(mocked_fs, path="")
