from pathlib import Path

import pytest

from dissect.target import Target
from dissect.target.loaders.velociraptor import VelociraptorLoader

from ._utils import absolute_path, mkdirs


@pytest.mark.parametrize(
    "paths",
    [
        (
            [
                "uploads.json",
                "uploads/mft/%5C%5C.%5CC%3A/",
                "uploads/mft/%5C%5C.%5CC%3A/$Extend",
                "uploads/mft/%5C%5C.%5CC%3A/windows/system32",
                "uploads/mft/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1",
            ]
        ),
        (
            [
                "uploads.json",
                "uploads/ntfs/%5C%5C.%5CC%3A/",
                "uploads/ntfs/%5C%5C.%5CC%3A/$Extend",
                "uploads/ntfs/%5C%5C.%5CC%3A/windows/system32",
                "uploads/ntfs/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1",
            ]
        ),
        (
            [
                "uploads.json",
                "uploads/ntfs_vss/%5C%5C.%5CC%3A/",
                "uploads/ntfs_vss/%5C%5C.%5CC%3A/$Extend",
                "uploads/ntfs_vss/%5C%5C.%5CC%3A/windows/system32",
                "uploads/ntfs_vss/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1",
            ]
        ),
        (
            [
                "uploads.json",
                "uploads/lazy_ntfs/%5C%5C.%5CC%3A/",
                "uploads/lazy_ntfs/%5C%5C.%5CC%3A/$Extend",
                "uploads/lazy_ntfs/%5C%5C.%5CC%3A/windows/system32",
                "uploads/lazy_ntfs/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1",
            ]
        ),
    ],
)
def test_velociraptor_loader_windows_ntfs(paths: list[str], mock_target: Target, tmp_path: Path) -> None:
    root = tmp_path
    mkdirs(root, paths)

    with open(absolute_path("data/mft.raw"), "rb") as fh:
        root.joinpath(paths[1]).joinpath("$MFT").write_bytes(fh.read(10 * 1025))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    root.joinpath(paths[2]).joinpath("$UsnJrnl%3A$J").write_bytes(data)

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(mock_target)

    # TODO: Add fake Secure:SDS and verify mft function
    assert len(list(mock_target.usnjrnl())) == 1

    # The 2 found directories + the fake NTFS filesystem
    assert len(mock_target.filesystems) == 3


@pytest.mark.parametrize(
    "paths",
    [
        (["uploads.json", "uploads/file/etc", "uploads/file/var"]),
        (["uploads.json", "uploads/auto/etc", "uploads/auto/var"]),
        (["uploads.json", "uploads/file/etc", "uploads/file/var", "uploads/file/opt"]),
        (["uploads.json", "uploads/auto/etc", "uploads/auto/var", "uploads/auto/opt"]),
        (["uploads.json", "uploads/file/Library", "uploads/file/Applications"]),
        (["uploads.json", "uploads/auto/Library", "uploads/auto/Applications"]),
    ],
)
def test_dir_loader_unix(paths: list[str], mock_target: Target, tmp_path: Path) -> None:
    root = tmp_path
    mkdirs(root, paths)

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(mock_target)

    assert len(mock_target.filesystems) == 1
