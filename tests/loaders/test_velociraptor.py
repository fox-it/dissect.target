import shutil
from pathlib import Path

import pytest

from dissect.target import Target
from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.loaders.velociraptor import VelociraptorLoader
from tests._utils import absolute_path, mkdirs


def create_root(sub_dir: str, tmp_path: Path) -> Path:
    paths = [
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/",
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/$Extend",
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/windows/system32",
        f"uploads/{sub_dir}/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1/",
        f"uploads/{sub_dir}/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1/$Extend",
        f"uploads/{sub_dir}/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1/windows/system32",
    ]
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")
    (root / f"uploads/{sub_dir}/%5C%5C.%5CC%3A/C-DRIVE.txt").write_bytes(b"{}")

    with open(absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw"), "rb") as fh:
        mft = fh.read(10 * 1025)

    root.joinpath(paths[0]).joinpath("$MFT").write_bytes(mft)
    root.joinpath(paths[3]).joinpath("$MFT").write_bytes(mft)

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    root.joinpath(paths[1]).joinpath("$UsnJrnl%3A$J").write_bytes(data)
    root.joinpath(paths[4]).joinpath("$UsnJrnl%3A$J").write_bytes(data)

    return root


@pytest.mark.parametrize(
    "sub_dir, other_dir",
    [
        ("mft", "auto"),
        ("ntfs", "auto"),
        ("ntfs_vss", "auto"),
        ("lazy_ntfs", "auto"),
        ("auto", "ntfs"),
    ],
)
def test_windows_ntfs(sub_dir: str, other_dir: str, target_bare: Target, tmp_path: Path) -> None:
    root = create_root(sub_dir, tmp_path)
    root.joinpath(f"uploads/{other_dir}/C%3A").mkdir(parents=True, exist_ok=True)
    root.joinpath(f"uploads/{other_dir}/C%3A/other.txt").write_text("my first file")

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(target_bare)
    target_bare.apply()

    assert "sysvol" in target_bare.fs.mounts
    assert "c:" in target_bare.fs.mounts

    usnjrnl_records = 0
    for fs in target_bare.filesystems:
        if isinstance(fs, NtfsFilesystem):
            usnjrnl_records += len(list(fs.ntfs.usnjrnl.records()))
    assert usnjrnl_records == 2
    assert len(target_bare.filesystems) == 4
    assert target_bare.fs.path("sysvol/C-DRIVE.txt").exists()
    assert target_bare.fs.path("sysvol/other.txt").read_text() == "my first file"


@pytest.mark.parametrize(
    "sub_dir",
    ["mft", "ntfs", "ntfs_vss", "lazy_ntfs", "auto"],
)
def test_windows_ntfs_zip(sub_dir: str, target_bare: Target, tmp_path: Path) -> None:
    create_root(sub_dir, tmp_path)

    shutil.make_archive(tmp_path.joinpath("test_ntfs"), "zip", tmp_path)

    zip_path = tmp_path.joinpath("test_ntfs.zip")
    assert VelociraptorLoader.detect(zip_path) is True

    loader = VelociraptorLoader(zip_path)
    loader.map(target_bare)
    target_bare.apply()

    assert "sysvol" in target_bare.fs.mounts
    assert "c:" in target_bare.fs.mounts

    usnjrnl_records = 0
    for fs in target_bare.filesystems:
        if isinstance(fs, NtfsFilesystem):
            usnjrnl_records += len(list(fs.ntfs.usnjrnl.records()))
    assert usnjrnl_records == 2
    assert len(target_bare.filesystems) == 4
    assert target_bare.fs.path("sysvol/C-DRIVE.txt").exists()


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
def test_unix(paths: list[str], target_bare: Target, tmp_path: Path) -> None:
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
def test_unix_zip(paths: list[str], target_bare: Target, tmp_path: Path) -> None:
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")

    shutil.make_archive(tmp_path.joinpath("test_unix"), "zip", tmp_path)

    zip_path = tmp_path.joinpath("test_unix.zip")
    assert VelociraptorLoader.detect(zip_path) is True

    loader = VelociraptorLoader(zip_path)
    loader.map(target_bare)

    assert len(target_bare.filesystems) == 1
