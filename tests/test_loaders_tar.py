from dissect.target import Target
from dissect.target.loaders.tar import TarLoader

from ._utils import absolute_path


def test_tar_loader_compressed_tar_file(target_win: Target):

    archive_path = absolute_path("data/test-archive.tar.gz")

    loader = TarLoader(archive_path)
    loader.map(target_win)

    assert len(target_win.filesystems) == 2

    test_file = target_win.fs.path("test-data/test-file.txt")

    assert test_file.exists()
    assert test_file.open().read() == b"test-value\n"


def test_tar_sensitive_drive_letter(target_win: Target):

    tar_file = absolute_path("data/uppercase_driveletter.tar")

    loader = TarLoader(tar_file)
    loader.map(target_win)

    assert len(target_win.fs.mounts) == 2
    assert "C:" not in target_win.fs.mounts.keys()
    assert target_win.fs.get("C:/test.file").open().read() == b"hello_world"
    assert target_win.fs.get("c:/test.file").open().read() == b"hello_world"
