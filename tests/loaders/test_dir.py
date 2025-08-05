from __future__ import annotations

from typing import TYPE_CHECKING, Callable

import pytest

from dissect.target.loader import open as loader_open
from dissect.target.loaders.dir import DirLoader, find_dirs
from dissect.target.plugin import OperatingSystem
from dissect.target.target import Target
from tests._utils import mkdirs

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("opener"),
    [
        pytest.param(Target.open, id="target-open"),
        pytest.param(lambda x: next(Target.open_all([x])), id="target-open-all"),
    ],
)
def test_target_open(opener: Callable[[str | Path], Target], tmp_path: Path) -> None:
    """Test that we correctly use ``DirLoader`` when opening a ``Target``."""
    root = tmp_path
    mkdirs(root, ["windows/system32"])

    target = opener(root)
    assert isinstance(target._loader, DirLoader)
    assert target.path == root


def test_windows(tmp_path: Path) -> None:
    """Test the ``DirLoader`` for Windows directories."""
    root = tmp_path
    mkdirs(root, ["windows/system32"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.WINDOWS
    assert len(dirs) == 1

    loader = loader_open(root)
    assert isinstance(loader, DirLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 1


def test_winnt(tmp_path: Path) -> None:
    """Test the ``DirLoader`` for WinNT directories."""
    root = tmp_path
    mkdirs(tmp_path, ["winnt"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.WINDOWS
    assert len(dirs) == 1

    loader = loader_open(root)
    assert isinstance(loader, DirLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 1


def test_windows_drive_letters(tmp_path: Path) -> None:
    """Test the ``DirLoader`` with Windows drive letters."""
    root = tmp_path
    mkdirs(root, ["C/windows/system32", "D/test", "E/test"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.WINDOWS
    assert len(dirs) == 3

    loader = loader_open(root)
    assert isinstance(loader, DirLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 3
    assert len(t.fs.mounts) == 3


def test_linux(tmp_path: Path) -> None:
    """Test the ``DirLoader`` for Linux directories."""
    root = tmp_path
    mkdirs(root, ["etc", "var"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.LINUX
    assert len(dirs) == 1

    loader = loader_open(root)
    assert isinstance(loader, DirLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 1


def test_macos(tmp_path: Path) -> None:
    """Test the ``DirLoader`` for macOS directories."""
    root = tmp_path
    mkdirs(root, ["Library"])

    os_type, dirs = find_dirs(root)
    assert os_type == OperatingSystem.OSX
    assert len(dirs) == 1

    loader = loader_open(root)
    assert isinstance(loader, DirLoader)

    t = Target()
    loader.map(t)
    assert len(t.filesystems) == 1
