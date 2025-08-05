from __future__ import annotations

from typing import TYPE_CHECKING, Callable
from unittest.mock import patch

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.kape import KapeLoader
from dissect.target.target import Target
from tests._utils import absolute_path, mkdirs

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def mock_kape_dir(tmp_path: Path) -> Path:
    root = tmp_path
    mkdirs(root, ["C/windows/system32", "C/$Extend", "D/test", "E/test"])

    # Only need this to exist up until the root directory record to make dissect.ntfs happy
    with absolute_path("_data/plugins/filesystem/ntfs/mft/mft.raw").open("rb") as fh:
        (root / "C/$MFT").write_bytes(fh.read(10 * 1024))

    # Add one record so we can test if it works
    data = bytes.fromhex(
        "5800000002000000c100000000000100bf000000000001002003010000000000"
        "6252641a86a4d7010381008000000000000000002000000018003c0069007300"
        "2d00310035005000320036002e0074006d00700000000000"
    )
    (root / "C/$Extend/$J").write_bytes(data)

    return root


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], mock_kape_dir: Path) -> None:
    """Test that we correctly use ``KapeLoader`` when opening a ``Target``."""
    for path in [mock_kape_dir, absolute_path("_data/loaders/kape/test.vhdx")]:
        target = opener(path)
        assert isinstance(target._loader, KapeLoader)
        assert target.path == path


@patch("dissect.target.filesystems.dir.DirectoryFilesystem.ntfs", None, create=True)
def test_dir(mock_kape_dir: Path) -> None:
    """Test the ``KapeLoader`` with a directory."""
    loader = loader_open(mock_kape_dir)
    assert isinstance(loader, KapeLoader)

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


def test_vhdx() -> None:
    """Test the ``KapeLoader`` with a VHDX file."""
    path = absolute_path("_data/loaders/kape/test.vhdx")

    loader = loader_open(path)
    assert KapeLoader.detect(path)

    t = Target()
    loader.map(t)
    t.apply()

    assert "sysvol" in t.fs.mounts
    assert "c:" in t.fs.mounts
