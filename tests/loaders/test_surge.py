from __future__ import annotations

import json
import zipfile
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

from dissect.target import Target
from dissect.target.loader import open as loader_open
from dissect.target.loaders.surge import SurgeLoader
from tests._utils import absolute_path, mkdirs


@pytest.fixture
def mock_surge_windows_dir(tmp_path: Path) -> Path:
    root = tmp_path / "20251218133700"

    mkdirs(
        root,
        [
            "api/windows",
            "files/C/windows/system32",
            "files/D/test",
            "files/E/test",
            "usn-journals",
        ],
    )

    # Required files for detection
    (root / "log.txt").touch()

    meta = {
        "platform": {
            "os": "Windows",
        }
    }
    (root / "meta.json").write_text(json.dumps(meta), encoding="utf-8")

    # Only need this to exist up until the root directory record to make dissect.ntfs happy
    with absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw").open("rb") as fh:
        (root / "files/C/$MFT").write_bytes(fh.read(10 * 1024))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    (root / "usn-journals/C").write_bytes(data)

    return root


@pytest.fixture
def mock_surge_windows_dir_with_missing_file(mock_surge_windows_dir: Path) -> Path:
    path = mock_surge_windows_dir
    (path / "log.txt").unlink()
    return path


@pytest.fixture
def mock_surge_macos_dir(tmp_path: Path) -> Path:
    root = tmp_path / "20251218133701"

    mkdirs(
        root,
        [
            "api/darwin",
            "files/etc",
            "files/Library",
            "files/Users",
        ],
    )

    (root / "log.txt").touch()
    (root / "files/etc/test.txt").touch()

    meta = {"platform": {"os": "Darwin"}}
    (root / "meta.json").write_text(json.dumps(meta), encoding="utf-8")

    return root


@pytest.fixture
def mock_surge_macos_dir_with_missing_dir(mock_surge_macos_dir: Path) -> Path:
    path = mock_surge_macos_dir
    (path / "api/darwin").rmdir()
    return path


@pytest.fixture
def mock_surge_linux_dir(tmp_path: Path) -> Path:
    root = tmp_path / "20251218133702"

    mkdirs(
        root,
        [
            "files/etc",
            "files/proc",
            "files/var",
        ],
    )

    (root / "log.txt").touch()
    (root / "files/etc/test.txt").touch()

    meta = {"platform": {"os": "Linux"}}
    (root / "meta.json").write_text(json.dumps(meta), encoding="utf-8")

    return root


def zip_dir(path: Path) -> Path:
    zip_path = path.with_suffix(".zip")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in path.rglob("*"):
            zf.write(item, item.relative_to(path))

    return zip_path


@pytest.mark.parametrize(
    ("should_detect", "fixture_name"),
    [
        (True, "mock_surge_windows_dir"),
        (False, "mock_surge_windows_dir_with_missing_file"),
        (True, "mock_surge_macos_dir"),
        (False, "mock_surge_macos_dir_with_missing_dir"),
        (True, "mock_surge_linux_dir"),
    ],
)
def test_detect(request: pytest.FixtureRequest, should_detect: bool, fixture_name: str) -> None:
    assert SurgeLoader.detect(request.getfixturevalue(fixture_name)) == should_detect


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open_for_valid_surge_targets(
    opener: Callable[[str | Path], Target],
    mock_surge_windows_dir: Path,
    mock_surge_macos_dir: Path,
    mock_surge_linux_dir: Path,
) -> None:
    """Test that we correctly use ``SurgeLoader`` when opening a ``Target``."""
    for dir in (
        mock_surge_windows_dir,
        mock_surge_macos_dir,
        mock_surge_linux_dir,
    ):
        surge_root = dir
        timestamped_root = surge_root.parent

        for path in (surge_root, timestamped_root):
            target = opener(path)
        assert isinstance(target._loader, SurgeLoader)
        assert target.path == path


def test_loader_with_windows_variants(mock_surge_windows_dir: Path) -> None:
    surge_root = mock_surge_windows_dir
    timestamped_root = surge_root.parent

    paths = [
        surge_root,
        timestamped_root,
        zip_dir(surge_root),
        zip_dir(timestamped_root),
    ]

    for path in paths:
        loader = loader_open(path)
        assert isinstance(loader, SurgeLoader)

        t = Target()
        loader.map(t)
        t.apply()

        assert "sysvol" in t.fs.mounts
        assert "c:" in t.fs.mounts
        assert "d:" in t.fs.mounts
        assert "e:" in t.fs.mounts

    # The 3 found drive letter directories + the fake NTFS filesystem
    assert len(t.filesystems) == 4
    # The 3 found drive letters + sysvol + the fake NTFS filesystem at /$fs$
    assert len(t.fs.mounts) == 5
    assert len(list(t.fs.mounts["c:"].ntfs.usnjrnl.records())) == 1


def test_loader_with_macos_variants(mock_surge_macos_dir: Path) -> None:
    surge_root = mock_surge_macos_dir
    timestamped_root = surge_root.parent

    paths = [
        surge_root,
        timestamped_root,
        zip_dir(surge_root),
        zip_dir(timestamped_root),
    ]

    for path in paths:
        loader = loader_open(path)
        assert isinstance(loader, SurgeLoader)

        t = Target()
        loader.map(t)
        t.apply()

        assert "/" in t.fs.mounts
        assert len(t.filesystems) == 1
        assert t.fs.path("/etc/test.txt").exists()


def test_loader_with_linux_variants(mock_surge_linux_dir: Path) -> None:
    surge_root = mock_surge_linux_dir
    timestamped_root = surge_root.parent

    paths = [
        surge_root,
        timestamped_root,
        zip_dir(surge_root),
        zip_dir(timestamped_root),
    ]

    for path in paths:
        loader = loader_open(path)
        assert isinstance(loader, SurgeLoader)

        t = Target()
        loader.map(t)
        t.apply()

        assert "/" in t.fs.mounts
        assert len(t.filesystems) == 1
        assert t.fs.path("/etc/test.txt").exists()
