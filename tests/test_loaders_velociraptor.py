from dissect.target.loaders.velociraptor import VelociraptorLoader

from ._utils import absolute_path, mkdirs


def test_velociraptor_loader_windows_ntfs(mock_target, tmp_path):
    root = tmp_path
    mkdirs(
        root,
        [
            "uploads.json",
            "uploads/mft/%5C%5C.%5CC%3A/$Extend",
            "uploads/mft/%5C%5C.%5CC%3A/windows/system32",
            "uploads/mft/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1",
            "uploads/mft/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy2",
        ],
    )

    with open(absolute_path("data/mft.raw"), "rb") as fh:
        (root / "uploads/mft/%5C%5C.%5CC%3A/$MFT").write_bytes(fh.read(10 * 1025))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    (root / "uploads/mft/%5C%5C.%5CC%3A/$Extend/$UsnJrnl%3A$J").write_bytes(data)

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(mock_target)

    assert len(list(mock_target.usnjrnl())) == 1

    # The 3 found directories + the fake NTFS filesystem
    assert len(mock_target.filesystems) == 4


def test_dir_loader_linux(mock_target, tmp_path):
    root = tmp_path
    mkdirs(root, ["uploads.json", "uploads/file/etc", "uploads/file/var"])

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1


def test_dir_loader_macos(mock_target, tmp_path):
    root = tmp_path
    mkdirs(root, ["uploads.json", "uploads/file/Library"])

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1
