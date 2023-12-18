import shutil
from pathlib import Path

import pytest

from dissect.target import Target
from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.loaders.velociraptor import VelociraptorLoader
from tests._utils import absolute_path, mkdirs


def create_paths(sub_dir: str) -> list[str]:
    return [
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/",
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/$Extend",
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/windows/system32",
        f"uploads/{sub_dir}/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1",
    ]


@pytest.mark.parametrize(
    "sub_dir",
    ["mft", "ntfs", "ntfs_vss", "lazy_ntfs", "auto"],
)
def test_velociraptor_loader_windows_ntfs(sub_dir: str, target_bare: Target, tmp_path: Path) -> None:
    paths = create_paths(sub_dir)
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")

    with open(absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw"), "rb") as fh:
        root.joinpath(paths[0]).joinpath("$MFT").write_bytes(fh.read(10 * 1025))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    root.joinpath(paths[1]).joinpath("$UsnJrnl%3A$J").write_bytes(data)

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(target_bare)

    # TODO: Add fake Secure:SDS and verify mft function
    usnjrnl_records = 0
    for fs in target_bare.filesystems:
        if isinstance(fs, NtfsFilesystem):
            usnjrnl_records += len(list(fs.ntfs.usnjrnl.records()))
    assert usnjrnl_records == 1

    # The 2 found directories + the fake NTFS filesystem
    assert len(target_bare.filesystems) == 3


@pytest.mark.parametrize(
    "sub_dir",
    ["mft", "ntfs", "ntfs_vss", "lazy_ntfs", "auto"],
)
def test_velociraptor_loader_windows_ntfs_zip(sub_dir: str, target_bare: Target, tmp_path: Path) -> None:
    paths = create_paths(sub_dir)
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")

    with open(absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw"), "rb") as fh:
        root.joinpath(paths[0]).joinpath("$MFT").write_bytes(fh.read(10 * 1025))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    root.joinpath(paths[1]).joinpath("$UsnJrnl%3A$J").write_bytes(data)

    shutil.make_archive(tmp_path.joinpath("test_ntfs"), "zip", tmp_path)

    zip_path = tmp_path.joinpath("test_ntfs.zip")
    assert VelociraptorLoader.detect(zip_path) is True

    loader = VelociraptorLoader(zip_path)
    loader.map(target_bare)

    usnjrnl_records = 0
    for fs in target_bare.filesystems:
        if isinstance(fs, NtfsFilesystem):
            usnjrnl_records += len(list(fs.ntfs.usnjrnl.records()))
    assert usnjrnl_records == 1
    assert len(target_bare.filesystems) == 3


@pytest.mark.parametrize(
    "paths",
    [
        (["uploads/file/etc", "uploads/file/var"]),
        (["uploads/auto/etc", "uploads/auto/var"]),
        (["uploads/file/etc", "uploads/file/var", "uploads/file/opt"]),
        (["uploads/auto/etc", "uploads/auto/var", "uploads/auto/opt"]),
        (["uploads/file/Library", "uploads/file/Applications"]),
        (["uploads/auto/Library", "uploads/auto/Applications"]),
    ],
)
def test_dir_loader_unix(paths: list[str], target_bare: Target, tmp_path: Path) -> None:
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 1


@pytest.mark.parametrize(
    "paths",
    [
        (["uploads/file/etc", "uploads/file/var"]),
        (["uploads/auto/etc", "uploads/auto/var"]),
        (["uploads/file/etc", "uploads/file/var", "uploads/file/opt"]),
        (["uploads/auto/etc", "uploads/auto/var", "uploads/auto/opt"]),
        (["uploads/file/Library", "uploads/file/Applications"]),
        (["uploads/auto/Library", "uploads/auto/Applications"]),
    ],
)
def test_dir_loader_unix_zip(paths: list[str], target_bare: Target, tmp_path: Path) -> None:
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")

    shutil.make_archive(tmp_path.joinpath("test_unix"), "zip", tmp_path)

    zip_path = tmp_path.joinpath("test_unix.zip")
    assert VelociraptorLoader.detect(zip_path) is True

    loader = VelociraptorLoader(zip_path)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 1
