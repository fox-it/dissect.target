from __future__ import annotations

import gzip
from unittest.mock import Mock, create_autospec

import pytest

from dissect.target.filesystems.fat import (
    FatFilesystem,
    FileNotFoundError,
    NotADirectoryError,
    fat_exc,
)
from tests._utils import absolute_path


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


@pytest.mark.parametrize(
    "file_path",
    [
        "_data/filesystems/fat/fat12.bin.gz",
        "_data/filesystems/fat/fat16.bin.gz",
        "_data/filesystems/fat/fat32.bin.gz",
    ],
)
def test_fat(file_path: str) -> None:
    with gzip.open(absolute_path(file_path), "rb") as fh:
        assert FatFilesystem.detect(fh)

        fs = FatFilesystem(fh)

        root = fs.get("/")

        dirents = {entry.name: entry for entry in root.scandir()}
        assert len(dirents) == 4

        assert dirents["subdir1"].is_dir()
        assert not dirents["file1.txt"].is_dir()

def test_exfat() -> None:
    with gzip.open(absolute_path("_data/filesystems/fat/exfat.bin.gz"), "rb") as fh:
        assert FatFilesystem.detect(fh)

        fs = FatFilesystem(fh)

        root = fs.get("/")

        dirents = {entry.name: entry for entry in root.scandir()}
        assert len(dirents) == 6

        assert dirents["directory"].is_dir()
        assert not dirents["cat.jpg"].is_dir()

