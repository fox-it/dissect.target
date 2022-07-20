from dissect.target.loaders.tar import TarLoader


from ._utils import absolute_path


def test_tar_loader_compressed_tar_file(target_win):

    archive_path = absolute_path("data/test-archive.tar.gz")

    loader = TarLoader(archive_path)
    loader.map(target_win)

    assert len(target_win.filesystems) == 2

    test_file = target_win.fs.path("test-data/test-file.txt")

    assert test_file.exists()
    assert test_file.open().read() == b"test-value\n"
