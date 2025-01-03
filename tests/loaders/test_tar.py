import pytest

from dissect.target import Target
from dissect.target.loaders.tar import TarLoader
from tests._utils import absolute_path


@pytest.mark.parametrize(
    "archive",
    [
        "_data/loaders/tar/test-archive.tar",
        "_data/loaders/tar/test-archive.tar.gz",
    ],
)
def test_tar_loader_compressed_tar_file(target_win: Target, archive) -> None:
    archive_path = absolute_path(archive)

    loader = TarLoader(archive_path)
    loader.map(target_win)

    assert len(target_win.filesystems) == 2

    test_file = target_win.fs.path("test-data/test-file.txt")

    assert test_file.exists()
    assert test_file.open().read() == b"test-value\n"


def test_tar_loader_compressed_tar_file_with_empty_dir(target_unix: Target) -> None:
    archive_path = absolute_path("_data/loaders/tar/test-archive-empty-folder.tgz")
    loader = TarLoader(archive_path)
    loader.map(target_unix)

    assert len(target_unix.filesystems) == 2
    test_file = target_unix.fs.path("test/test_file_with_content")
    assert test_file.exists()
    assert test_file.is_file()
    assert test_file.open().read() == b"This is a test!\n"
    empty_folder = target_unix.fs.path("test/empty_dir")
    assert empty_folder.exists()
    assert empty_folder.is_dir()
