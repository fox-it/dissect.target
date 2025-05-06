from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

import pytest

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.loaders.velociraptor import VelociraptorLoader
from tests._utils import absolute_path, mkdirs

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


def create_root(sub_dir: str, tmp_path: Path) -> Path:
    paths = [
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/",
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/$Extend",
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/windows/system32",
        f"uploads/{sub_dir}/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1/",
        f"uploads/{sub_dir}/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1/$Extend",
        f"uploads/{sub_dir}/%5C%5C%3F%5CGLOBALROOT%5CDevice%5CHarddiskVolumeShadowCopy1/windows/system32",
        f"uploads/{sub_dir}/%5C%5C.%5CC%3A/%2ETEST",
        "results",
    ]
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")
    (root / f"uploads/{sub_dir}/%5C%5C.%5CC%3A/C-DRIVE.txt").write_bytes(b"{}")
    (root / f"uploads/{sub_dir}/%5C%5C.%5CC%3A/Microsoft-Windows-Windows Defender%254WHC.evtx").write_bytes(b"{}")
    (root / f"uploads/{sub_dir}/%5C%5C.%5CC%3A/other.txt").write_text("my first file")

    with absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw").open("rb") as fh:
        mft = fh.read(10 * 1024)

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
    "sub_dir",
    ["mft", "ntfs", "ntfs_vss", "lazy_ntfs", "auto"],
)
def test_windows_ntfs(sub_dir: str, target_bare: Target, tmp_path: Path) -> None:
    root = create_root(sub_dir, tmp_path)

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
    assert target_bare.fs.path("sysvol/.TEST").exists()
    assert target_bare.fs.path("sysvol/Microsoft-Windows-Windows Defender%254WHC.evtx").exists()


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
    assert target_bare.fs.path("sysvol/.TEST").exists()
    assert target_bare.fs.path("sysvol/Microsoft-Windows-Windows Defender%4WHC.evtx").exists()


@pytest.mark.parametrize(
    "paths",
    [
        (["uploads/file/etc", "uploads/file/var", "uploads/file/%2ETEST"]),
        (["uploads/auto/etc", "uploads/auto/var", "uploads/auto/%2ETEST"]),
        (["uploads/file/etc", "uploads/file/var", "uploads/file/opt", "uploads/file/%2ETEST"]),
        (["uploads/auto/etc", "uploads/auto/var", "uploads/auto/opt", "uploads/auto/%2ETEST"]),
        (["uploads/file/Library", "uploads/file/Applications", "uploads/file/%2ETEST"]),
        (["uploads/auto/Library", "uploads/auto/Applications", "uploads/auto/%2ETEST"]),
    ],
)
def test_unix(paths: list[str], target_bare: Target, tmp_path: Path) -> None:
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(target_bare)
    target_bare.apply()

    assert len(target_bare.filesystems) == 1
    assert target_bare.fs.path("/.TEST").exists()


@pytest.mark.parametrize(
    "paths",
    [
        (["uploads/file/etc", "uploads/file/var", "uploads/file/%2ETEST"]),
        (["uploads/auto/etc", "uploads/auto/var", "uploads/auto/%2ETEST"]),
        (["uploads/file/etc", "uploads/file/var", "uploads/file/opt", "uploads/file/%2ETEST"]),
        (["uploads/auto/etc", "uploads/auto/var", "uploads/auto/opt", "uploads/auto/%2ETEST"]),
        (["uploads/file/Library", "uploads/file/Applications", "uploads/file/%2ETEST"]),
        (["uploads/auto/Library", "uploads/auto/Applications", "uploads/auto/%2ETEST"]),
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
    target_bare.apply()

    assert len(target_bare.filesystems) == 1
    assert target_bare.fs.path("/.TEST").exists()
