from __future__ import annotations

import shutil
from typing import TYPE_CHECKING, Callable

import pytest

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.target.loader import open as loader_open
from dissect.target.loaders.velociraptor import VelociraptorLoader
from dissect.target.target import Target
from tests._utils import absolute_path, mkdirs

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(params=["mft", "ntfs", "ntfs_vss", "lazy_ntfs", "auto"])
def mock_velociraptor_dir(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    sub_dir = request.param
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
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], mock_velociraptor_dir: Path) -> None:
    """Test that we correctly use ``VelociraptorLoader`` when opening a ``Target``."""
    path = mock_velociraptor_dir

    target = opener(path)
    assert isinstance(target._loader, VelociraptorLoader)
    assert target.path == path


def test_windows_ntfs(mock_velociraptor_dir: Path) -> None:
    """Test that ``VelociraptorLoader`` correctly loads a Windows directory structure."""
    loader = loader_open(mock_velociraptor_dir)
    assert isinstance(loader, VelociraptorLoader)

    t = Target()
    loader.map(t)
    t.apply()

    assert "sysvol" in t.fs.mounts
    assert "c:" in t.fs.mounts

    usnjrnl_records = 0
    for fs in t.filesystems:
        if isinstance(fs, NtfsFilesystem):
            usnjrnl_records += len(list(fs.ntfs.usnjrnl.records()))
    assert usnjrnl_records == 2
    assert len(t.filesystems) == 4

    assert t.fs.path("sysvol/C-DRIVE.txt").exists()
    assert t.fs.path("sysvol/other.txt").read_text() == "my first file"
    assert t.fs.path("sysvol/.TEST").exists()
    assert t.fs.path("sysvol/Microsoft-Windows-Windows Defender%254WHC.evtx").exists()


def test_windows_ntfs_zip(mock_velociraptor_dir: Path) -> None:
    """Test that ``VelociraptorLoader`` correctly loads a Windows ZIP structure."""
    shutil.make_archive(mock_velociraptor_dir.joinpath("test_ntfs"), "zip", mock_velociraptor_dir)

    path = mock_velociraptor_dir.joinpath("test_ntfs.zip")
    loader = loader_open(path)
    assert isinstance(loader, VelociraptorLoader)

    t = Target()
    loader.map(t)
    t.apply()

    assert "sysvol" in t.fs.mounts
    assert "c:" in t.fs.mounts

    usnjrnl_records = 0
    for fs in t.filesystems:
        if isinstance(fs, NtfsFilesystem):
            usnjrnl_records += len(list(fs.ntfs.usnjrnl.records()))
    assert usnjrnl_records == 2
    assert len(t.filesystems) == 4
    assert t.fs.path("sysvol/C-DRIVE.txt").exists()
    assert t.fs.path("sysvol/.TEST").exists()
    assert t.fs.path("sysvol/Microsoft-Windows-Windows Defender%4WHC.evtx").exists()


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
def test_unix(paths: list[str], tmp_path: Path) -> None:
    """Test that ``VelociraptorLoader`` correctly loads a Unix directory structure."""
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")

    loader = loader_open(root)
    assert isinstance(loader, VelociraptorLoader)

    t = Target()
    loader.map(t)
    t.apply()

    assert len(t.filesystems) == 1
    assert t.fs.path("/.TEST").exists()


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
def test_unix_zip(paths: list[str], tmp_path: Path) -> None:
    """Test that ``VelociraptorLoader`` correctly loads a Unix ZIP structure."""
    root = tmp_path
    mkdirs(root, paths)

    (root / "uploads.json").write_bytes(b"{}")

    shutil.make_archive(tmp_path.joinpath("test_unix"), "zip", tmp_path)

    path = tmp_path.joinpath("test_unix.zip")
    loader = loader_open(path)
    assert isinstance(loader, VelociraptorLoader)

    t = Target()
    loader.map(t)
    t.apply()

    assert len(t.filesystems) == 1
    assert t.fs.path("/.TEST").exists()
